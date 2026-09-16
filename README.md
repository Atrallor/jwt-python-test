# Backend de Autenticación con SQLite, JWT Cifrado y Cifrado E2EE de Payloads

Sistema de autenticación completo y seguro desarrollado en Python (**Flask**, **SQLAlchemy** con SQLite, **PyJWT**, **Bcrypt** y **Cryptography**) y Frontend con **Web Crypto API**.

---

## 🔒 Arquitectura de Seguridad y Cifrado

### 1. Cifrado Extremo a Extremo de Payloads (E2EE HTTP)
* **Algoritmo**: **AES-256-GCM** (Galois/Counter Mode con nonce/IV aleatorio de 96 bits y etiqueta de autenticación de 128 bits).
* **Derivación de Clave**: SHA-256 a partir de `PAYLOAD_SECRET_KEY` o `JWT_SECRET_KEY`.
* **Transporte**: Todo el cuerpo de las peticiones (`POST /api/register`, `POST /api/login`, etc.) y de las respuestas HTTP viaja cifrado en un envoltorio Base64URL:
  ```json
  {
    "encrypted_payload": "<iv_12bytes + ciphertext + auth_tag_16bytes_base64url>",
    "encrypted": true,
    "algorithm": "AES-256-GCM"
  }
  ```

### 2. Tokens JWT con Claims Cifrados (Nested Encrypted JWT)
* El payload del JWT no expone ningún dato del usuario en texto plano ni en Base64 legible.
* Los datos de identidad (`id`, `email`, `username`, `name`, `lastname`) se cifran con AES-256-GCM dentro del claim `enc_data`.
* El token completo es firmado criptográficamente con **HS256** para garantizar integridad y no-repudio.

---

## 📁 Estructura del Proyecto

```text
jwt-python-test/
├── backend/
│   ├── db.py              # SQLite y Modelo ORM 'Usuario' (tabla: 'usuarios')
│   ├── crypto_service.py  # Cifrado/descifrado AES-256-GCM y derivación de clave
│   ├── token_builder.py   # Generación y validación de tokens JWT con claims cifrados
│   ├── email_service.py   # Servicio para envío de código de recuperación por email
│   ├── controller.py      # Endpoints con soporte de payloads cifrados
│   └── server.py          # Servidor Flask y servicio de frontend estático
├── frontend/
│   ├── index.html         # Interfaz web interactiva con inspector de cifrado
│   ├── styles.css         # Estilos modernos y dark mode
│   ├── crypto.js          # Motor Web Crypto API (AES-256-GCM en el navegador)
│   └── app.js             # Lógica cliente y conexión segura con la API
├── requirements.txt       # Dependencias del backend
└── README.md
```

---

## 🚀 Instalación y Ejecución

### 1. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 2. Iniciar el servidor

Desde la raíz del proyecto:
```bash
python backend/server.py
```
O dentro de `backend/`:
```bash
python server.py
```

Abre tu navegador en: `http://localhost:5000`

---

## 📌 Endpoints de la API

### 0. **Estado Criptográfico**
- **Método**: `GET`
- **Ruta**: `/api/crypto/info`
- **Respuesta (200 OK)**:
  ```json
  {
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
    }
  }
  ```

---

### 1. **Registro de Usuario**
- **Método**: `POST`
- **Ruta**: `/api/register`
- **Cuerpo Cifrado E2EE**:
  ```json
  {
    "encrypted_payload": "<AES_256_GCM_ENCRYPTED_BASE64>"
  }
  ```
- *Contenido plano subyacente*:
  ```json
  {
    "email": "usuario@ejemplo.com",
    "username": "usuario123",
    "name": "Juan",
    "lastname": "Pérez",
    "password": "miPasswordSeguro"
  }
  ```

---

### 2. **Inicio de Sesión (Login)**
- **Método**: `POST`
- **Ruta**: `/api/login`
- **Cuerpo Cifrado E2EE**:
  ```json
  {
    "encrypted_payload": "<AES_256_GCM_ENCRYPTED_BASE64>"
  }
  ```
- **Respuesta Cifrada (200 OK)**:
  ```json
  {
    "encrypted_payload": "<AES_256_GCM_ENCRYPTED_BASE64>",
    "encrypted": true
  }
  ```
- *Contenido descifrado recibido por el cliente*:
  ```json
  {
    "message": "Inicio de sesión exitoso",
    "token": "<JWT_TOKEN_CON_CLAIMS_CIFRADOS>",
    "user": {
      "id": "uuid-generado",
      "email": "usuario@ejemplo.com",
      "username": "usuario123",
      "name": "Juan",
      "lastname": "Pérez"
    }
  }
  ```

---

### 3. **Recuperación de Contraseña**
- **Paso 1 (Solicitar Código)**: `POST /api/request-reset-code`
- **Paso 2 (Confirmar Código y Nueva Contraseña)**: `POST /api/reset-password`
