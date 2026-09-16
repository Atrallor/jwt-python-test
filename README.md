# Backend de Autenticación con SQLite y JWT

Backend en Python construido con **Flask**, **SQLAlchemy** (ORM con SQLite), **PyJWT** y **Bcrypt**.

---

## 📁 Estructura del Proyecto

```text
jwt-python-test/
├── backend/
│   ├── db.py              # SQLite y Modelo ORM 'Usuario' (tabla: 'usuarios')
│   ├── token_builder.py   # Generación y decodificación de tokens JWT
│   ├── email_service.py   # Servicio para envío de código de recuperación por email
│   ├── controller.py      # Endpoints: register, login, request-reset-code, reset-password
│   └── server.py          # Servidor Flask y activación de la API
├── requirements.txt       # Dependencias
└── README.md
```

---

## 🚀 Instalación y Ejecución

### 1. Instalar dependencias

```bash
pip install -r requirements.txt
```

O individualmente:
```bash
pip install sqlalchemy pyjwt bcrypt flask flask-cors
```

### 2. Iniciar el servidor

Desde la raíz:
```bash
python backend/server.py
```
O dentro de `backend/`:
```bash
python server.py
```

El servidor iniciará en `http://localhost:5000`.

---

## 📌 Endpoints de la API

### 1. **Registro de Usuario**
- **Método**: `POST`
- **Ruta**: `/api/register`
- **Body (JSON)**:
  ```json
  {
    "email": "usuario@ejemplo.com",
    "username": "usuario123",
    "name": "Juan",
    "lastname": "Pérez",
    "password": "miPasswordSeguro"
  }
  ```
- **Respuesta (201 Created)**:
  ```json
  {
    "message": "Usuario registrado exitosamente",
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

### 2. **Inicio de Sesión (Login)**
- **Método**: `POST`
- **Ruta**: `/api/login`
- **Body (JSON)**:
  ```json
  {
    "email": "usuario@ejemplo.com",
    "password": "miPasswordSeguro"
  }
  ```
  *(También se puede enviar `"username": "usuario123"` en lugar de `email`)*
- **Respuesta (200 OK)**:
  ```json
  {
    "message": "Inicio de sesión exitoso",
    "token": "<JWT_TOKEN>",
    "user": {
      "id": "uuid-generado",
      "email": "usuario@ejemplo.com",
      "username": "usuario123",
      "name": "Juan",
      "lastname": "Pérez"
    }
  }
  ```
- **Payload del Token JWT**: Contiene la información del usuario (`id`, `email`, `username`, `name`, `lastname`) sin incluir la contraseña.

---

### 3. **Paso 1: Solicitar Código de Recuperación de Contraseña**
- **Método**: `POST`
- **Ruta**: `/api/request-reset-code` (o `/api/forgot-password`)
- **Body (JSON)**:
  ```json
  {
    "email": "usuario@ejemplo.com"
  }
  ```
- **Respuesta (200 OK)**:
  ```json
  {
    "message": "Código de recuperación enviado al correo asociado",
    "email": "usuario@ejemplo.com"
  }
  ```
- *Nota*: En desarrollo se muestra el código de 6 dígitos en la consola del servidor. Si defines variables de entorno SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`), se enviará el correo real.

---

### 4. **Paso 2: Restablecer Contraseña con Código**
- **Método**: `POST` o `PUT`
- **Ruta**: `/api/reset-password`
- **Body (JSON)**:
  ```json
  {
    "email": "usuario@ejemplo.com",
    "code": "123456",
    "new_password": "miNuevaPassword123"
  }
  ```
- **Respuesta (200 OK)**:
  ```json
  {
    "message": "Contraseña restablecida exitosamente",
    "user": {
      "id": "uuid-generado",
      "email": "usuario@ejemplo.com",
      "username": "usuario123",
      "name": "Juan",
      "lastname": "Pérez"
    }
  }
  ```
