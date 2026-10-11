"""Claves de identidad de PRUEBA (no son secretos: se generan solo para el entorno de pruebas)."""
import base64
import os

os.environ.setdefault("MUV_JWT_PRIVATE_KEY", base64.b64encode(bytes(range(32))).decode())
# Clave Fernet valida (32 bytes en base64 urlsafe).
os.environ.setdefault("MUV_TOTP_KEY", base64.urlsafe_b64encode(bytes(range(32, 64))).decode())
