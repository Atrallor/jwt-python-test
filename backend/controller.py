import random
import string
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, g
import bcrypt
from backend.db import SessionLocal, Usuario
from backend.token_builder import generate_token, decode_token
from backend.email_service import send_reset_code_email
from backend.crypto_service import encrypt_payload, decrypt_payload

auth_bp = Blueprint("auth", __name__)

def hash_password(password: str) -> str:
    """Hashea una contraseña usando bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def check_password(password: str, hashed_password: str) -> bool:
    """Verifica si la contraseña coincide con el hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))

def generate_verification_code(length: int = 6) -> str:
    """Genera un código numérico aleatorio de verificación."""
    return "".join(random.choices(string.digits, k=length))

def get_request_data() -> tuple[dict | None, bool]:
    """
    Extrae y descifra los datos de la solicitud entrante.
    Soporta payloads cifrados con AES-256-GCM en el campo 'encrypted_payload' o 'data',
    así como solicitudes JSON estándar para compatibilidad.
    Retorna: (data_dict, is_encrypted_flag)
    """
    raw_json = request.get_json(silent=True)
    if not raw_json or not isinstance(raw_json, dict):
        return None, False

    # Verificar si el payload viene cifrado
    encrypted_payload = raw_json.get("encrypted_payload") or raw_json.get("data")
    if encrypted_payload and isinstance(encrypted_payload, str):
        try:
            decrypted = decrypt_payload(encrypted_payload)
            if isinstance(decrypted, dict):
                return decrypted, True
            return None, True
        except Exception as e:
            return None, True

    # Si no venía cifrado pero trae header explícito
    if request.headers.get("X-Encrypted-Payload") == "true":
        return None, True

    return raw_json, False

def create_api_response(data: dict, status_code: int = 200, is_encrypted: bool = False):
    """
    Crea una respuesta JSON. Si el cliente envió una solicitud cifrada o lo requiere,
    cifra todo el cuerpo de respuesta con AES-256-GCM.
    """
    # Si la petición original fue cifrada o se solicita por header
    wants_encrypted = is_encrypted or request.headers.get("X-Encrypted-Response") == "true"
    
    if wants_encrypted:
        try:
            encrypted_data = encrypt_payload(data)
            return jsonify({
                "encrypted_payload": encrypted_data,
                "encrypted": True,
                "algorithm": "AES-256-GCM"
            }), status_code
        except Exception as e:
            return jsonify({"error": f"Error al cifrar respuesta: {str(e)}"}), 500

    return jsonify(data), status_code


# ==========================================
# 0. Endpoint: Crypto Status & Info
# ==========================================
@auth_bp.route("/crypto/info", methods=["GET"])
@auth_bp.route("/crypto-status", methods=["GET"])
def crypto_status():
    """Retorna información sobre los algoritmos criptográficos activos en la API."""
    return jsonify({
        "status": "active",
        "payload_encryption": {
            "algorithm": "AES-256-GCM",
            "key_size_bits": 256,
            "iv_size_bits": 96,
            "tag_size_bits": 128,
            "encoding": "Base64URL"
        },
        "token_encryption": {
            "type": "Nested Encrypted JWT",
            "claims_encryption": "AES-256-GCM",
            "token_signature": "HS256"
        },
        "password_hashing": "Bcrypt"
    }), 200


# ==========================================
# 1. Endpoint: Register
# ==========================================
@auth_bp.route("/register", methods=["POST"])
def register():
    data, is_encrypted = get_request_data()
    if not data:
        return create_api_response(
            {"error": "No se recibieron datos válidos (o error al descifrar payload)"}, 
            400, 
            is_encrypted
        )

    required_fields = ["email", "username", "name", "lastname", "password"]
    for field in required_fields:
        if not data.get(field):
            return create_api_response(
                {"error": f"El campo '{field}' es requerido"}, 
                400, 
                is_encrypted
            )

    email = str(data["email"]).strip().lower()
    username = str(data["username"]).strip().lower()
    name = str(data["name"]).strip()
    lastname = str(data["lastname"]).strip()
    password = str(data["password"])

    db = SessionLocal()
    try:
        # Verificar si el email o username ya existen
        existing_user = db.query(Usuario).filter(
            (Usuario.email == email) | (Usuario.username == username)
        ).first()

        if existing_user:
            if existing_user.email == email:
                return create_api_response({"error": "El correo electrónico ya está registrado"}, 409, is_encrypted)
            if existing_user.username == username:
                return create_api_response({"error": "El nombre de usuario ya está registrado"}, 409, is_encrypted)

        # Crear nuevo usuario con contraseña hasheada
        hashed_pw = hash_password(password)
        new_user = Usuario(
            email=email,
            username=username,
            name=name,
            lastname=lastname,
            password=hashed_pw
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return create_api_response({
            "message": "Usuario registrado exitosamente",
            "user": new_user.to_dict()
        }, 201, is_encrypted)

    except Exception as e:
        db.rollback()
        return create_api_response({"error": f"Error interno del servidor: {str(e)}"}, 500, is_encrypted)
    finally:
        db.close()


# ==========================================
# 2. Endpoint: Login
# ==========================================
@auth_bp.route("/login", methods=["POST"])
def login():
    data, is_encrypted = get_request_data()
    if not data:
        return create_api_response(
            {"error": "No se recibieron credenciales válidas (o error al descifrar payload)"}, 
            400, 
            is_encrypted
        )

    # Permitir inicio de sesión con email o username
    identifier = data.get("email") or data.get("username")
    password = data.get("password")

    if not identifier or not password:
        return create_api_response({"error": "Se requiere email/username y contraseña"}, 400, is_encrypted)

    identifier = str(identifier).strip().lower()
    password = str(password)

    db = SessionLocal()
    try:
        # Buscar usuario por email o por username
        user = db.query(Usuario).filter(
            (Usuario.email == identifier) | (Usuario.username == identifier)
        ).first()

        if not user or not check_password(password, user.password):
            return create_api_response({"error": "Credenciales inválidas"}, 401, is_encrypted)

        # Generar token JWT con claims cifrados mediante AES-256-GCM
        user_info = user.to_dict()
        token = generate_token(user_info, encrypt=True)

        return create_api_response({
            "message": "Inicio de sesión exitoso",
            "token": token,
            "user": user_info
        }, 200, is_encrypted)

    except Exception as e:
        return create_api_response({"error": f"Error interno del servidor: {str(e)}"}, 500, is_encrypted)
    finally:
        db.close()


# ==========================================
# 3. Endpoint: Solicitar código para resetear contraseña
# ==========================================
@auth_bp.route("/request-reset-code", methods=["POST"])
@auth_bp.route("/forgot-password", methods=["POST"])
@auth_bp.route("/reset-password/request", methods=["POST"])
def request_reset_code():
    data, is_encrypted = get_request_data()
    if not data:
        return create_api_response({"error": "No se recibieron datos válidos"}, 400, is_encrypted)

    identifier = data.get("email") or data.get("username")
    if not identifier:
        return create_api_response({"error": "Se requiere el campo 'email' o 'username'"}, 400, is_encrypted)

    identifier = str(identifier).strip().lower()

    db = SessionLocal()
    try:
        user = db.query(Usuario).filter(
            (Usuario.email == identifier) | (Usuario.username == identifier)
        ).first()

        if not user:
            return create_api_response(
                {"error": "No se encontró ningún usuario con ese correo o nombre de usuario"}, 
                404, 
                is_encrypted
            )

        # Generar código numérico de 6 dígitos
        code = generate_verification_code(6)
        user.reset_code = code
        user.reset_code_expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        db.commit()

        # Enviar el código al correo electrónico asociado
        success, email_status = send_reset_code_email(user.email, code, user.name)

        response_data = {
            "message": "Código de recuperación generado y procesado",
            "email": user.email,
            "smtp_sent": success
        }

        if not success:
            response_data["warning"] = email_status
            response_data["message"] = f"El código fue generado, pero falló el envío de correo: {email_status}"

        return create_api_response(response_data, 200, is_encrypted)

    except Exception as e:
        db.rollback()
        return create_api_response({"error": f"Error interno del servidor: {str(e)}"}, 500, is_encrypted)
    finally:
        db.close()


# ==========================================
# 4. Endpoint: Confirmar y restablecer contraseña con código
# ==========================================
@auth_bp.route("/reset-password", methods=["POST", "PUT"])
@auth_bp.route("/reset_password", methods=["POST", "PUT"])
def reset_password():
    data, is_encrypted = get_request_data()
    if not data:
        return create_api_response({"error": "No se recibieron datos válidos"}, 400, is_encrypted)

    identifier = data.get("email") or data.get("username")
    code = data.get("code")
    new_password = data.get("new_password") or data.get("password")

    if not identifier:
        return create_api_response({"error": "Se requiere el campo 'email' o 'username'"}, 400, is_encrypted)
    if not code:
        return create_api_response({"error": "Se requiere el código de verificación 'code'"}, 400, is_encrypted)
    if not new_password:
        return create_api_response({"error": "Se requiere la nueva contraseña 'new_password'"}, 400, is_encrypted)

    identifier = str(identifier).strip().lower()
    code = str(code).strip()

    db = SessionLocal()
    try:
        user = db.query(Usuario).filter(
            (Usuario.email == identifier) | (Usuario.username == identifier)
        ).first()

        if not user:
            return create_api_response({"error": "Usuario no encontrado"}, 404, is_encrypted)

        # Validar si tiene un código pendiente
        if not user.reset_code or not user.reset_code_expires_at:
            return create_api_response(
                {"error": "No se ha solicitado ningún código de recuperación o ya fue utilizado"}, 
                400, 
                is_encrypted
            )

        # Validar que el código coincida
        if user.reset_code != code:
            return create_api_response({"error": "El código de verificación es incorrecto"}, 400, is_encrypted)

        # Validar que no haya expirado
        now = datetime.now(timezone.utc)
        expires_at = user.reset_code_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            return create_api_response(
                {"error": "El código de verificación ha expirado. Solicita uno nuevo"}, 
                400, 
                is_encrypted
            )

        # Código válido: actualizar contraseña y limpiar código
        user.password = hash_password(str(new_password))
        user.reset_code = None
        user.reset_code_expires_at = None
        db.commit()

        return create_api_response({
            "message": "Contraseña restablecida exitosamente",
            "user": user.to_dict()
        }, 200, is_encrypted)

    except Exception as e:
        db.rollback()
        return create_api_response({"error": f"Error interno del servidor: {str(e)}"}, 500, is_encrypted)
    finally:
        db.close()
