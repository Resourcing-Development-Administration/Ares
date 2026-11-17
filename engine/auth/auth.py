"""
Sistema JWT + bcrypt para autenticación de Ares.

Dependencias: passlib[bcrypt], python-jose[cryptography]
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta

from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import HTTPException

_ARES_DIR = Path.home() / ".ares"
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_jwt_secret() -> str:
    """Lee ARES_JWT_SECRET del env; si no existe lo genera (32 bytes hex),
    lo escribe en ~/.ares/jwt.key y lo setea en os.environ."""
    secret = os.environ.get("ARES_JWT_SECRET")
    if secret:
        return secret
    key_file = _ARES_DIR / "jwt.key"
    if key_file.exists():
        secret = key_file.read_text(encoding="utf-8").strip()
    else:
        secret = secrets.token_hex(32)
        _ARES_DIR.mkdir(parents=True, exist_ok=True)
        key_file.write_text(secret, encoding="utf-8")
        key_file.chmod(0o600)
    os.environ["ARES_JWT_SECRET"] = secret
    return secret


def hash_password(pwd: str) -> str:
    """Genera bcrypt hash de la contraseña."""
    return _pwd_context.hash(pwd)


def verify_password(plain: str, hashed: str) -> bool:
    """Verifica una contraseña en texto plano contra un bcrypt hash."""
    return _pwd_context.verify(plain, hashed)


def create_token(user_id: str = "admin", exp_hours: int = 24) -> str:
    """Genera un JWT HS256 con payload {sub, iat, exp}."""
    secret = get_jwt_secret()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(hours=exp_hours),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def validate_token(token: str) -> dict:
    """Valida un JWT y retorna el payload. Lanza HTTPException(401) si inválido/expirado."""
    secret = get_jwt_secret()
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Token inválido o expirado: {exc}")


def get_admin_hash() -> str:
    """Lee ARES_ADMIN_HASH del env; si no existe, genera hash de ARES_ADMIN_PASSWORD
    (default 'changeme'), lo guarda en ~/.ares/admin.hash y env."""
    admin_hash = os.environ.get("ARES_ADMIN_HASH")
    if admin_hash:
        return admin_hash
    hash_file = _ARES_DIR / "admin.hash"
    if hash_file.exists():
        admin_hash = hash_file.read_text(encoding="utf-8").strip()
    else:
        password = os.environ.get("ARES_ADMIN_PASSWORD", "changeme")
        admin_hash = hash_password(password)
        _ARES_DIR.mkdir(parents=True, exist_ok=True)
        hash_file.write_text(admin_hash, encoding="utf-8")
        hash_file.chmod(0o600)
    os.environ["ARES_ADMIN_HASH"] = admin_hash
    return admin_hash
