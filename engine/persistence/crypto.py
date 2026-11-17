"""
Cifrado AES-256-GCM para secretos en reposo.

Formato de texto cifrado: enc:v1:<base64(nonce + ciphertext + tag)>
- nonce:      12 bytes  (AES-GCM standard)
- ciphertext: variable
- tag:        16 bytes  (GCM authentication tag)

Clave maestra: ARES_ENCRYPTION_KEY (hex de 32 bytes = 64 chars hex, o base64 de 32 bytes).
Si no está configurada, encrypt() falla con RuntimeError — nunca silencia la ausencia de clave.
"""
from __future__ import annotations
import base64
import binascii
import os

_PREFIX = "enc:v1:"
_NONCE_LEN = 12
_TAG_LEN = 16


def _load_key() -> bytes:
    raw = os.environ.get("ARES_ENCRYPTION_KEY", "").strip()
    if not raw:
        raise RuntimeError(
            "ARES_ENCRYPTION_KEY no configurada — "
            "setá una clave hex de 32 bytes (64 chars) o base64 de 32 bytes"
        )
    # intentar hex primero
    if len(raw) == 64:
        try:
            key = binascii.unhexlify(raw)
            if len(key) == 32:
                return key
        except (ValueError, binascii.Error):
            pass
    # intentar base64
    try:
        key = base64.b64decode(raw)
        if len(key) == 32:
            return key
    except Exception:
        pass
    raise RuntimeError(
        f"ARES_ENCRYPTION_KEY inválida: se esperan 32 bytes (hex 64 chars o base64), "
        f"se recibieron {len(raw)} chars"
    )


def encrypt(plaintext: str) -> str:
    """Cifra plaintext con AES-256-GCM y devuelve el token enc:v1:..."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _load_key()
    nonce = os.urandom(_NONCE_LEN)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt devuelve ciphertext + tag concatenados
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext.encode(), None)
    blob = nonce + ciphertext_and_tag
    return _PREFIX + base64.b64encode(blob).decode()


def decrypt(token: str) -> str:
    """Descifra un token enc:v1:... y devuelve el plaintext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not token.startswith(_PREFIX):
        raise ValueError(f"token no tiene el prefijo esperado '{_PREFIX}'")
    b64 = token[len(_PREFIX):]
    try:
        blob = base64.b64decode(b64)
    except Exception as exc:
        raise ValueError(f"token mal formado (base64 inválido): {exc}") from exc

    if len(blob) < _NONCE_LEN + _TAG_LEN:
        raise ValueError("token demasiado corto para nonce + tag")

    nonce = blob[:_NONCE_LEN]
    ciphertext_and_tag = blob[_NONCE_LEN:]
    key = _load_key()
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except Exception as exc:
        raise ValueError(f"descifrado fallido (clave incorrecta o datos corruptos): {exc}") from exc
    return plaintext_bytes.decode()


def is_encrypted(value: str) -> bool:
    """Devuelve True si value es un token cifrado."""
    return isinstance(value, str) and value.startswith(_PREFIX)


def encrypt_if_needed(value: str) -> str:
    """Cifra value solo si no está ya cifrado. Noop si ARES_ENCRYPTION_KEY no está seteada."""
    if is_encrypted(value):
        return value
    if not os.environ.get("ARES_ENCRYPTION_KEY", "").strip():
        return value
    return encrypt(value)


def decrypt_if_needed(value: str) -> str:
    """Descifra value solo si está cifrado. Pass-through si no lo está."""
    if is_encrypted(value):
        return decrypt(value)
    return value
