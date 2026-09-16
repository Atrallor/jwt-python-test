import os
import datetime
import hashlib
import jwt
from backend.crypto_service import encrypt_payload, decrypt_payload, DEFAULT_SECRET

# Clave secreta para firmar tokens JWT (se puede sobreescribir mediante variable de entorno)
raw_secret = os.getenv("JWT_SECRET_KEY") or DEFAULT_SECRET
SECRET_KEY = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest() if len(raw_secret) < 32 else raw_secret
ALGORITHM = "HS256"
EXPIRATION_MINUTES = 1

def generate_token(user_payload: dict, expires_in_minutes: int = EXPIRATION_MINUTES, encrypt: bool = True) -> str:
    """
    Genera un token JWT cifrado (Nested Encrypted JWT con AES-256-GCM y firma HS256).
    Cifra los datos del usuario en la propiedad 'enc_data' para que ningún dato sensible
    quede expuesto en texto plano en el payload del token.
    """
    # Filtrar contraseña
    clean_user = {k: v for k, v in user_payload.items() if k != "password"}
    
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + datetime.timedelta(minutes=expires_in_minutes)

    if encrypt:
        # Cifrar todos los datos de usuario con AES-256-GCM
        encrypted_claims = encrypt_payload(clean_user)
        jwt_payload = {
            "enc_data": encrypted_claims,
            "enc": "AES-256-GCM",
            "iat": now,
            "exp": exp
        }
    else:
        jwt_payload = dict(clean_user)
        jwt_payload["iat"] = now
        jwt_payload["exp"] = exp

    token = jwt.encode(jwt_payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def decode_token(token: str, decrypt: bool = True) -> dict:
    """
    Decodifica y valida la firma y expiración del token JWT.
    Si contiene claims cifrados ('enc_data'), los descifra automáticamente con AES-256-GCM.
    """
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    
    if decrypt and "enc_data" in payload:
        try:
            user_data = decrypt_payload(payload["enc_data"])
            if isinstance(user_data, dict):
                # Unir datos descifrados manteniendo metadatos iat, exp y enc
                result = dict(payload)
                result.update(user_data)
                return result
        except Exception as e:
            raise ValueError(f"Fallo al descifrar el payload del token: {str(e)}")
            
    return payload
