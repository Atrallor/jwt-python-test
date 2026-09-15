import os
import datetime
import jwt

# Clave secreta para firmar tokens JWT (se puede sobreescribir mediante variable de entorno)
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt_secret_super_secure_key_2026")
ALGORITHM = "HS256"
EXPIRATION_MINUTES = 1

def generate_token(user_payload: dict, expires_in_minutes: int = EXPIRATION_MINUTES) -> str:
    """
    Genera un token JWT incluyendo la información del usuario en el payload.
    Excluye explícitamente el campo password si viniera en el payload.
    Expiración por defecto configurada a 15 minutos.
    """
    payload = {k: v for k, v in user_payload.items() if k != "password"}
    
    # Agregar tiempos de emisión y expiración
    now = datetime.datetime.now(datetime.timezone.utc)
    payload["iat"] = now
    payload["exp"] = now + datetime.timedelta(minutes=expires_in_minutes)

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def decode_token(token: str) -> dict:
    """
    Decodifica y valida un token JWT.
    Lanza excepciones de PyJWT si es inválido o ha expirado.
    """
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
