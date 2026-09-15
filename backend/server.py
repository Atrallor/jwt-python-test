import sys
import os

# Asegurar que la ruta raíz del proyecto esté en sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"))
    load_dotenv() # También carga .env local si existe
except ImportError:
    pass

FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from backend.db import init_db
from backend.controller import auth_bp

def create_app():
    app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
    CORS(app)

    # Inicializar las tablas de la base de datos SQLite
    init_db()

    # Registrar rutas del controlador
    app.register_blueprint(auth_bp, url_prefix="/api")
    app.register_blueprint(auth_bp, name="auth_direct", url_prefix="")

    @app.route("/", methods=["GET"])
    def index():
        # Servir la interfaz web premium desde el frontend
        if os.path.exists(os.path.join(FRONTEND_DIR, "index.html")):
            return send_from_directory(FRONTEND_DIR, "index.html")
        return jsonify({
            "status": "online",
            "message": "API de Autenticacion con SQLite y JWT activa",
            "endpoints": {
                "register": "POST /api/register",
                "login": "POST /api/login",
                "request_reset_code": "POST /api/request-reset-code (o /forgot-password)",
                "reset_password": "POST /api/reset-password (con code y new_password)"
            }
        }), 200

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy"}), 200

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f" Servidor iniciado en http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
