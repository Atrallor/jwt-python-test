import random
import string
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify
import bcrypt
from backend.db import SessionLocal, Usuario
from backend.token_builder import generate_token
from backend.email_service import send_reset_code_email

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


# ==========================================
# 1. Endpoint: Register
# ==========================================
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No se recibieron datos en formato JSON"}), 400

    required_fields = ["email", "username", "name", "lastname", "password"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"El campo '{field}' es requerido"}), 400

    email = data["email"].strip().lower()
    username = data["username"].strip().lower()
    name = data["name"].strip()
    lastname = data["lastname"].strip()
    password = data["password"]

    db = SessionLocal()
    try:
        # Verificar si el email o username ya existen
        existing_user = db.query(Usuario).filter(
            (Usuario.email == email) | (Usuario.username == username)
        ).first()

        if existing_user:
            if existing_user.email == email:
                return jsonify({"error": "El correo electrónico ya está registrado"}), 409
            if existing_user.username == username:
                return jsonify({"error": "El nombre de usuario ya está registrado"}), 409

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

        return jsonify({
            "message": "Usuario registrado exitosamente",
            "user": new_user.to_dict()
        }), 201

    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Error interno del servidor: {str(e)}"}), 500
    finally:
        db.close()


# ==========================================
# 2. Endpoint: Login
# ==========================================
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No se recibieron datos en formato JSON"}), 400

    # Permitir inicio de sesión con email o username
    identifier = data.get("email") or data.get("username")
    password = data.get("password")

    if not identifier or not password:
        return jsonify({"error": "Se requiere email/username y contraseña"}), 400

    identifier = identifier.strip().lower()

    db = SessionLocal()
    try:
        # Buscar usuario por email o por username (ambos en lowercase)
        user = db.query(Usuario).filter(
            (Usuario.email == identifier) | (Usuario.username == identifier)
        ).first()

        if not user or not check_password(password, user.password):
            return jsonify({"error": "Credenciales inválidas"}), 401

        # Generar token JWT con la información del usuario (sin la contraseña)
        user_info = user.to_dict()
        token = generate_token(user_info)

        return jsonify({
            "message": "Inicio de sesión exitoso",
            "token": token
        }), 200

    except Exception as e:
        return jsonify({"error": f"Error interno del servidor: {str(e)}"}), 500
    finally:
        db.close()


# ==========================================
# 3. Endpoint: Solicitar código para resetear contraseña
# ==========================================
@auth_bp.route("/request-reset-code", methods=["POST"])
@auth_bp.route("/forgot-password", methods=["POST"])
@auth_bp.route("/reset-password/request", methods=["POST"])
def request_reset_code():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No se recibieron datos en formato JSON"}), 400

    identifier = data.get("email") or data.get("username")
    if not identifier:
        return jsonify({"error": "Se requiere el campo 'email' o 'username'"}), 400

    identifier = identifier.strip().lower()

    db = SessionLocal()
    try:
        user = db.query(Usuario).filter(
            (Usuario.email == identifier) | (Usuario.username == identifier)
        ).first()

        if not user:
            return jsonify({"error": "No se encontró ningún usuario con ese correo o nombre de usuario"}), 404

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

        return jsonify(response_data), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Error interno del servidor: {str(e)}"}), 500
    finally:
        db.close()


# ==========================================
# 4. Endpoint: Confirmar y restablecer contraseña con código
# ==========================================
@auth_bp.route("/reset-password", methods=["POST", "PUT"])
@auth_bp.route("/reset_password", methods=["POST", "PUT"])
def reset_password():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No se recibieron datos en formato JSON"}), 400

    identifier = data.get("email") or data.get("username")
    code = data.get("code")
    new_password = data.get("new_password") or data.get("password")

    if not identifier:
        return jsonify({"error": "Se requiere el campo 'email' o 'username'"}), 400
    if not code:
        return jsonify({"error": "Se requiere el código de verificación 'code'"}), 400
    if not new_password:
        return jsonify({"error": "Se requiere la nueva contraseña 'new_password'"}), 400

    identifier = identifier.strip().lower()
    code = str(code).strip()

    db = SessionLocal()
    try:
        user = db.query(Usuario).filter(
            (Usuario.email == identifier) | (Usuario.username == identifier)
        ).first()

        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        # Validar si tiene un código pendiente
        if not user.reset_code or not user.reset_code_expires_at:
            return jsonify({"error": "No se ha solicitado ningún código de recuperación o ya fue utilizado"}), 400

        # Validar que el código coincida
        if user.reset_code != code:
            return jsonify({"error": "El código de verificación es incorrecto"}), 400

        # Validar que no haya expirado
        now = datetime.now(timezone.utc)
        expires_at = user.reset_code_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            return jsonify({"error": "El código de verificación ha expirado. Solicita uno nuevo"}), 400

        # Código válido: actualizar contraseña y limpiar código
        user.password = hash_password(new_password)
        user.reset_code = None
        user.reset_code_expires_at = None
        db.commit()

        return jsonify({
            "message": "Contraseña restablecida exitosamente",
            "user": user.to_dict()
        }), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Error interno del servidor: {str(e)}"}), 500
    finally:
        db.close()
