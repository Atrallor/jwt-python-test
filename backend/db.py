import os
import uuid
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# Ruta base de la base de datos SQLite
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.sqlite")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(120), unique=True, nullable=False, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    name = Column(String(80), nullable=False)
    lastname = Column(String(80), nullable=False)
    password = Column(String(255), nullable=False)
    reset_code = Column(String(10), nullable=True)
    reset_code_expires_at = Column(DateTime, nullable=True)

    def to_dict(self, include_password: bool = False) -> dict:
        data = {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "name": self.name,
            "lastname": self.lastname
        }
        if include_password:
            data["password"] = self.password
        return data

    def __repr__(self):
        return f"<Usuario(id='{self.id}', username='{self.username}', email='{self.email}')>"

def init_db():
    """Crea las tablas y asegura las columnas necesarias en la base de datos."""
    Base.metadata.create_all(bind=engine)

    # Migración liviana para agregar columnas si la tabla ya existía previamente
    with engine.connect() as conn:
        inspector = inspect(engine)
        if "usuarios" in inspector.get_table_names():
            columns = [col["name"] for col in inspector.get_columns("usuarios")]
            if "reset_code" not in columns:
                conn.execute(text("ALTER TABLE usuarios ADD COLUMN reset_code VARCHAR(10)"))
            if "reset_code_expires_at" not in columns:
                conn.execute(text("ALTER TABLE usuarios ADD COLUMN reset_code_expires_at DATETIME"))
            conn.commit()

def get_db():
    """Generador de sesión de base de datos."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
