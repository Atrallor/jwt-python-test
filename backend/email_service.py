import os
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Cargar automáticamente el archivo .env desde la raíz o backend
try:
    from dotenv import load_dotenv
    base_dir = Path(__file__).resolve().parent.parent
    root_env = base_dir / ".env"
    backend_env = Path(__file__).resolve().parent / ".env"
    
    if root_env.exists():
        load_dotenv(dotenv_path=root_env)
    elif backend_env.exists():
        load_dotenv(dotenv_path=backend_env)
    else:
        load_dotenv()
except Exception:
    pass

def send_reset_code_email(to_email: str, code: str, username: str = "") -> tuple[bool, str]:
    """
    Envía el código de restablecimiento de contraseña por correo electrónico.
    Retorna (True, mensaje_exito) o (False, detalle_error).
    """
    # Intentar recargar .env en caso de cambios en tiempo de ejecución
    try:
        from dotenv import load_dotenv
        base_dir = Path(__file__).resolve().parent.parent
        root_env = base_dir / ".env"
        if root_env.exists():
            load_dotenv(dotenv_path=root_env, override=True)
    except Exception:
        pass

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port_raw = os.getenv("SMTP_PORT", "587")
    try:
        smtp_port = int(smtp_port_raw)
    except (ValueError, TypeError):
        smtp_port = 587

    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", smtp_user or "no-reply@authapp.com")

    subject = "Codigo de recuperacion de contrasena"
    body_text = f"""Hola {username or 'usuario'},

Has solicitado restablecer tu contrasena.
Tu codigo de verificacion es: {code}

Este codigo es valido por 15 minutos. Si no solicitaste este cambio, puedes ignorar este mensaje.
"""

    # Siempre mostrar en consola para facilitar desarrollo y depuración
    print("\n" + "=" * 60)
    print("[SERVICIO DE CORREO - RESET CODE]")
    print(f"Para: {to_email}")
    print(f"Asunto: {subject}")
    print(f"Codigo de recuperacion: {code}")
    if smtp_host and smtp_user:
        print(f"SMTP: {smtp_host}:{smtp_port} (Usuario: {smtp_user})")
    else:
        print("SMTP: No configurado o faltan variables en .env (Simulado en consola)")
    print("=" * 60 + "\n")

    # Si hay configuración SMTP completa, intentar envío real
    if smtp_host and smtp_user and smtp_password:
        try:
            msg = MIMEMultipart()
            msg["From"] = smtp_from
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body_text, "plain", "utf-8"))

            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=12) as server:
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)

            print(f"[OK] Correo enviado exitosamente via SMTP a {to_email}")
            return True, "Correo enviado exitosamente"
        except smtplib.SMTPAuthenticationError as e:
            error_msg = f"Error de autenticacion SMTP en {smtp_host}. Verifica si tu cuenta requiere una 'Contraseña de Aplicacion' de 16 caracteres de Google (App Password): {e}"
            print(f"[ERROR] {error_msg}")
            return False, error_msg
        except smtplib.SMTPConnectError as e:
            error_msg = f"No se pudo conectar al servidor SMTP {smtp_host}:{smtp_port}: {e}"
            print(f"[ERROR] {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = f"Fallo al enviar correo via SMTP: {str(e)}"
            print(f"[ERROR] {error_msg}")
            return False, error_msg

    return True, "Modo simulacion (sin credenciales SMTP en .env)"
