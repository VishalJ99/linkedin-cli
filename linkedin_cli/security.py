"""Security primitives for browser pairing and private LinkedIn sessions.

This module deliberately keeps secret handling small and explicit.  It does not
log secret material, and authentication failures are collapsed into stable
exceptions so callers cannot accidentally expose cryptographic details.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import secrets
import threading
import time
from typing import Any
from typing import Union

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error
from argon2.exceptions import InvalidHashError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from itsdangerous import BadData
from itsdangerous import SignatureExpired
from itsdangerous import URLSafeTimedSerializer


COOKIE_KEY_BYTES = 32
COOKIE_NONCE_BYTES = 12
PAIRING_TOKEN_BYTES = 32
APP_SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
APP_SESSION_SALT = "linkedin-contact-finder.app-session.v1"
_APP_SESSION_VERSION = 1


class SecurityConfigurationError(ValueError):
    """Raised when a security primitive is configured incorrectly."""


class CookiePayloadError(ValueError):
    """Raised when a cookie payload cannot be safely serialized."""


class CookieDecryptionError(ValueError):
    """Raised when encrypted cookie data is invalid or unauthenticated."""


class SessionTokenError(ValueError):
    """Raised when an application session token cannot be trusted."""


class SessionTokenExpired(SessionTokenError):
    """Raised when an otherwise signed application session has expired."""


@dataclass(frozen=True)
class EncryptedCookiePayload:
    """Base64url-encoded AES-GCM envelope suitable for database storage."""

    nonce: str
    ciphertext: str

    def as_dict(self) -> dict[str, str]:
        """Return a JSON-safe representation for persistence."""
        return {"nonce": self.nonce, "ciphertext": self.ciphertext}


@dataclass(frozen=True)
class AppSession:
    """Trusted identity recovered from a signed application session token."""

    user_id: str
    session_generation: str


@dataclass
class _AttemptWindow:
    started_at: float
    attempts: int


def generate_cookie_key() -> str:
    """Generate a base64url AES-256 key for ``COOKIE_ENCRYPTION_KEY``."""
    return _encode_base64url(secrets.token_bytes(COOKIE_KEY_BYTES))


class CookieCipher:
    """Encrypt JSON-safe cookie payloads with authenticated AES-256-GCM."""

    def __init__(self, encoded_key: Union[str, bytes]) -> None:
        key = _decode_cookie_key(encoded_key)
        self._cipher = AESGCM(key)

    @classmethod
    def from_encoded_key(cls, encoded_key: Union[str, bytes]) -> "CookieCipher":
        """Build a cipher from a standard or URL-safe base64 key."""
        return cls(encoded_key)

    def encrypt(
        self,
        cookie_payload: Any,
        *,
        aad: Union[str, bytes],
    ) -> EncryptedCookiePayload:
        """Serialize and encrypt a JSON-safe cookie payload.

        A fresh 96-bit nonce is generated for every call.  The caller-provided
        additional authenticated data should bind the envelope to its owner or
        database row and must be supplied again during decryption.
        """
        plaintext = _serialize_json(cookie_payload)
        nonce = secrets.token_bytes(COOKIE_NONCE_BYTES)
        ciphertext = self._cipher.encrypt(nonce, plaintext, _aad_bytes(aad))
        return EncryptedCookiePayload(
            nonce=_encode_base64url(nonce),
            ciphertext=_encode_base64url(ciphertext),
        )

    def decrypt(
        self,
        payload: EncryptedCookiePayload,
        *,
        aad: Union[str, bytes],
    ) -> Any:
        """Authenticate, decrypt, and parse an encrypted cookie payload."""
        if not isinstance(payload, EncryptedCookiePayload):
            raise CookieDecryptionError("Encrypted cookie payload is invalid.")

        try:
            nonce = _decode_base64url(payload.nonce)
            ciphertext = _decode_base64url(payload.ciphertext)
            if len(nonce) != COOKIE_NONCE_BYTES:
                raise ValueError
            plaintext = self._cipher.decrypt(nonce, ciphertext, _aad_bytes(aad))
            return json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise CookieDecryptionError(
                "Encrypted cookie payload could not be authenticated."
            ) from None


def generate_pairing_token() -> str:
    """Return a URL-safe pairing token with 256 bits of entropy."""
    return secrets.token_urlsafe(PAIRING_TOKEN_BYTES)


def hash_pairing_token(token: str) -> str:
    """Return the SHA-256 digest stored for a single-use pairing token."""
    if not isinstance(token, str) or not token:
        raise ValueError("Pairing token must be a non-empty string.")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_pairing_token(token: str, expected_hash: str) -> bool:
    """Constant-time compare a presented pairing token with its stored hash."""
    if not isinstance(token, str) or not token:
        return False
    if not isinstance(expected_hash, str):
        return False

    presented_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    # Compare fixed-length byte digests even when the stored value is malformed.
    try:
        stored_digest = bytes.fromhex(expected_hash)
    except ValueError:
        stored_digest = b""
    presented_digest = bytes.fromhex(presented_hash)
    return hmac.compare_digest(presented_digest, stored_digest)


class InvitePassword:
    """Verify an invite passcode against an Argon2 encoded hash."""

    def __init__(self, encoded_hash: str) -> None:
        if not isinstance(encoded_hash, str) or not encoded_hash:
            raise SecurityConfigurationError("An Argon2 password hash is required.")
        self._encoded_hash = encoded_hash
        self._hasher = PasswordHasher()

    def verify(self, password: str) -> bool:
        """Return whether ``password`` matches, without exposing either input."""
        if not isinstance(password, str):
            return False
        try:
            return self._hasher.verify(self._encoded_hash, password)
        except (Argon2Error, InvalidHashError, TypeError):
            return False


class AppSessionSigner:
    """Issue and verify signed, seven-day application user sessions."""

    def __init__(
        self,
        secret_key: Union[str, bytes],
        *,
        max_age_seconds: int = APP_SESSION_MAX_AGE_SECONDS,
    ) -> None:
        if not isinstance(secret_key, (str, bytes)) or not secret_key:
            raise SecurityConfigurationError("An application session secret is required.")
        if not isinstance(max_age_seconds, int):
            raise SecurityConfigurationError("Session max age must be an integer.")
        self._serializer = URLSafeTimedSerializer(
            secret_key,
            salt=APP_SESSION_SALT,
            signer_kwargs={"digest_method": hashlib.sha256},
        )
        self._max_age_seconds = max_age_seconds

    def issue(self, user_id: str, session_generation: str) -> str:
        """Issue a signed token identifying one application user."""
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("User ID must be a non-empty string.")
        if not isinstance(session_generation, str) or not session_generation:
            raise ValueError("Session generation must be a non-empty string.")
        return self._serializer.dumps(
            {
                "v": _APP_SESSION_VERSION,
                "user_id": user_id,
                "session_generation": session_generation,
            }
        )

    def verify(self, token: str) -> AppSession:
        """Authenticate a session token and recover its trusted identity."""
        if not isinstance(token, str) or not token:
            raise SessionTokenError("Application session token is invalid.")
        try:
            payload = self._serializer.loads(token, max_age=self._max_age_seconds)
        except SignatureExpired:
            raise SessionTokenExpired("Application session token has expired.") from None
        except BadData:
            raise SessionTokenError("Application session token is invalid.") from None

        if not isinstance(payload, dict):
            raise SessionTokenError("Application session token is invalid.")
        if payload.get("v") != _APP_SESSION_VERSION:
            raise SessionTokenError("Application session token is invalid.")
        user_id = payload.get("user_id")
        session_generation = payload.get("session_generation")
        if (
            not isinstance(user_id, str)
            or not user_id
            or not isinstance(session_generation, str)
            or not session_generation
        ):
            raise SessionTokenError("Application session token is invalid.")
        return AppSession(user_id=user_id, session_generation=session_generation)


class LoginThrottle:
    """Bound passcode verification attempts per source within one app process."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        window_seconds: int = 15 * 60,
        max_subjects: int = 2_048,
    ) -> None:
        if max_attempts < 1 or window_seconds < 1 or max_subjects < 1:
            raise ValueError("Login throttle limits must be positive.")
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._max_subjects = max_subjects
        self._windows: dict[str, _AttemptWindow] = {}
        self._lock = threading.Lock()

    def reserve(self, subject: str, *, now: float | None = None) -> int:
        """Reserve one verification; return retry-after seconds when blocked."""
        if not subject:
            subject = "unknown"
        current = time.monotonic() if now is None else now
        with self._lock:
            window = self._windows.get(subject)
            if window is None or current - window.started_at >= self._window_seconds:
                self._make_capacity(subject)
                self._windows[subject] = _AttemptWindow(current, 1)
                return 0
            if window.attempts >= self._max_attempts:
                remaining = self._window_seconds - (current - window.started_at)
                return max(1, math.ceil(remaining))
            window.attempts += 1
            return 0

    def reset(self, subject: str) -> None:
        with self._lock:
            self._windows.pop(subject, None)

    def _make_capacity(self, incoming_subject: str) -> None:
        if incoming_subject in self._windows or len(self._windows) < self._max_subjects:
            return
        oldest = min(self._windows, key=lambda key: self._windows[key].started_at)
        self._windows.pop(oldest, None)


def _serialize_json(payload: Any) -> bytes:
    try:
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        raise CookiePayloadError("Cookie payload must contain only JSON-safe values.") from None
    return serialized.encode("utf-8")


def _aad_bytes(aad: Union[str, bytes]) -> bytes:
    if isinstance(aad, str):
        return aad.encode("utf-8")
    if isinstance(aad, bytes):
        return aad
    raise TypeError("Additional authenticated data must be text or bytes.")


def _decode_cookie_key(encoded_key: Union[str, bytes]) -> bytes:
    if isinstance(encoded_key, str):
        try:
            encoded = encoded_key.encode("ascii")
        except UnicodeEncodeError:
            raise SecurityConfigurationError(
                "Cookie encryption key must be a base64-encoded 32-byte key."
            ) from None
    elif isinstance(encoded_key, bytes):
        encoded = encoded_key
    else:
        raise SecurityConfigurationError(
            "Cookie encryption key must be a base64-encoded 32-byte key."
        )

    try:
        key = _decode_base64url(encoded)
    except (TypeError, ValueError):
        raise SecurityConfigurationError(
            "Cookie encryption key must be valid base64 encoding exactly 32 bytes."
        ) from None
    if len(key) != COOKIE_KEY_BYTES:
        raise SecurityConfigurationError(
            "Cookie encryption key must decode to exactly 32 bytes for AES-256-GCM."
        )
    return key


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: Union[str, bytes]) -> bytes:
    if isinstance(value, str):
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("Invalid base64 value.") from None
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise TypeError("Base64 value must be text or bytes.")
    if not encoded:
        raise ValueError("Base64 value cannot be empty.")

    padding = b"=" * (-len(encoded) % 4)
    try:
        return base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Invalid base64 value.") from None
