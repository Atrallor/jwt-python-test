import os
import json
import base64
import hashlib
from typing import Any, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Clave secreta compartida por defecto o configurable vía variable de entorno
DEFAULT_SECRET = "jwt-python-test-secure-aes256gcm-key"

def get_secret(custom_secret: str | None = None) -> str:
    """Obtiene la clave secreta desde parámetros, variables de entorno o valor predeterminado."""
    if custom_secret:
        return custom_secret
    return os.getenv("PAYLOAD_SECRET_KEY") or os.getenv("JWT_SECRET_KEY") or DEFAULT_SECRET

def get_aes_key(secret: str | None = None) -> bytes:
    """
    Deriva una clave AES de 256 bits (32 bytes) a partir del secreto usando SHA-256.
    """
    secret_str = get_secret(secret)
    return hashlib.sha256(secret_str.encode("utf-8")).digest()

def encrypt_payload(data: Any, secret: str | None = None) -> str:
    """
    Cifra cualquier dato (diccionario, lista, string o primitivo) usando AES-256-GCM.
    Estructura binaria: [12 bytes IV / Nonce] + [Ciphertext] + [16 bytes GCM Tag]
    Retorna un string codificado en Base64 URL-Safe.
    """
    if not isinstance(data, str):
        payload_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
    else:
        payload_bytes = data.encode("utf-8")

    key = get_aes_key(secret)
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # Nonce de 96 bits recomendado para AES-GCM
    
    # AESGCM.encrypt añade la etiqueta de autenticación al final del texto cifrado
    ciphertext_with_tag = aesgcm.encrypt(iv, payload_bytes, None)
    
    # Concatenar IV + Ciphertext (con Tag)
    encrypted_blob = iv + ciphertext_with_tag
    return base64.urlsafe_b64encode(encrypted_blob).decode("utf-8")

def decrypt_payload(encrypted_b64: str, secret: str | None = None) -> Any:
    """
    Descifra un payload cifrado con AES-256-GCM en formato Base64.
    Extrae los primeros 12 bytes como IV y el resto como Ciphertext + Tag.
    Retorna el objeto deserializado (JSON) o un string.
    """
    if not encrypted_b64 or not isinstance(encrypted_b64, str):
        raise ValueError("El payload cifrado debe ser un string no vacío")

    # Corregir padding de Base64 si falta
    b64_str = encrypted_b64.strip()
    padding = len(b64_str) % 4
    if padding:
        b64_str += "=" * (4 - padding)

    # Intentar decodificar como URL-safe o base64 estándar
    try:
        raw_bytes = base64.urlsafe_b64decode(b64_str)
    except Exception:
        raw_bytes = base64.b64decode(b64_str)

    if len(raw_bytes) < 28:  # 12 bytes IV + 16 bytes auth tag mínimos
        raise ValueError("Longitud de payload cifrado inválida o corrupta")

    iv = raw_bytes[:12]
    ciphertext_with_tag = raw_bytes[12:]

    key = get_aes_key(secret)
    aesgcm = AESGCM(key)
    
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)
    decrypted_str = decrypted_bytes.decode("utf-8")

    try:
        return json.loads(decrypted_str)
    except json.JSONDecodeError:
        return decrypted_str
