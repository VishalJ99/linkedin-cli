from __future__ import annotations

import base64

from argon2 import PasswordHasher
import pytest

from linkedin_cli.security import APP_SESSION_MAX_AGE_SECONDS
from linkedin_cli.security import AppSessionSigner
from linkedin_cli.security import CookieCipher
from linkedin_cli.security import CookieDecryptionError
from linkedin_cli.security import CookiePayloadError
from linkedin_cli.security import EncryptedCookiePayload
from linkedin_cli.security import InvitePassword
from linkedin_cli.security import SecurityConfigurationError
from linkedin_cli.security import SessionTokenError
from linkedin_cli.security import SessionTokenExpired
from linkedin_cli.security import generate_cookie_key
from linkedin_cli.security import generate_pairing_token
from linkedin_cli.security import hash_pairing_token
from linkedin_cli.security import verify_pairing_token


@pytest.fixture
def encoded_cookie_key() -> str:
    return base64.urlsafe_b64encode(b"k" * 32).decode("ascii")


@pytest.fixture
def cookie_payload() -> list[dict[str, object]]:
    return [
        {
            "name": "li_at",
            "value": "cookie-secret-value",
            "domain": ".linkedin.com",
            "secure": True,
        },
        {
            "name": "JSESSIONID",
            "value": '"ajax:123"',
            "domain": ".linkedin.com",
            "secure": True,
        },
    ]


def test_cookie_cipher_round_trip(encoded_cookie_key, cookie_payload) -> None:
    cipher = CookieCipher(encoded_cookie_key)

    encrypted = cipher.encrypt(cookie_payload, aad="user:123")

    assert cipher.decrypt(encrypted, aad="user:123") == cookie_payload
    assert encrypted.as_dict() == {
        "nonce": encrypted.nonce,
        "ciphertext": encrypted.ciphertext,
    }


def test_cookie_cipher_uses_unique_nonce(encoded_cookie_key, cookie_payload) -> None:
    cipher = CookieCipher(encoded_cookie_key)

    first = cipher.encrypt(cookie_payload, aad=b"user:123")
    second = cipher.encrypt(cookie_payload, aad=b"user:123")

    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext


def test_cookie_ciphertext_does_not_contain_plaintext(encoded_cookie_key, cookie_payload) -> None:
    encrypted = CookieCipher(encoded_cookie_key).encrypt(cookie_payload, aad="user:123")

    stored_envelope = f"{encrypted.nonce}:{encrypted.ciphertext}"
    assert "cookie-secret-value" not in stored_envelope
    assert "ajax:123" not in stored_envelope


def test_cookie_cipher_rejects_wrong_aad(encoded_cookie_key, cookie_payload) -> None:
    cipher = CookieCipher(encoded_cookie_key)
    encrypted = cipher.encrypt(cookie_payload, aad="user:123")

    with pytest.raises(CookieDecryptionError):
        cipher.decrypt(encrypted, aad="user:456")


def test_cookie_cipher_rejects_wrong_key(encoded_cookie_key, cookie_payload) -> None:
    encrypted = CookieCipher(encoded_cookie_key).encrypt(cookie_payload, aad="user:123")
    wrong_key = base64.b64encode(b"w" * 32).decode("ascii")

    with pytest.raises(CookieDecryptionError):
        CookieCipher(wrong_key).decrypt(encrypted, aad="user:123")


@pytest.mark.parametrize("field", ["nonce", "ciphertext"])
def test_cookie_cipher_rejects_tampered_envelope(
    encoded_cookie_key,
    cookie_payload,
    field,
) -> None:
    cipher = CookieCipher(encoded_cookie_key)
    encrypted = cipher.encrypt(cookie_payload, aad="user:123")
    original_value = getattr(encrypted, field)
    replacement = "A" if original_value[0] != "A" else "B"
    tampered_value = replacement + original_value[1:]
    tampered = EncryptedCookiePayload(
        nonce=tampered_value if field == "nonce" else encrypted.nonce,
        ciphertext=tampered_value if field == "ciphertext" else encrypted.ciphertext,
    )

    with pytest.raises(CookieDecryptionError):
        cipher.decrypt(tampered, aad="user:123")


@pytest.mark.parametrize(
    "invalid_key",
    [
        "not base64!",
        base64.urlsafe_b64encode(b"short").decode("ascii"),
        base64.urlsafe_b64encode(b"x" * 31).decode("ascii"),
        base64.urlsafe_b64encode(b"x" * 33).decode("ascii"),
        "",
    ],
)
def test_cookie_cipher_rejects_invalid_keys(invalid_key) -> None:
    with pytest.raises(SecurityConfigurationError, match="32 bytes|32-byte"):
        CookieCipher(invalid_key)


def test_generate_cookie_key_returns_aes_256_key() -> None:
    encoded_key = generate_cookie_key()

    assert len(base64.urlsafe_b64decode(encoded_key + "==")) == 32
    assert CookieCipher.from_encoded_key(encoded_key)


def test_cookie_cipher_rejects_non_json_payload(encoded_cookie_key) -> None:
    with pytest.raises(CookiePayloadError):
        CookieCipher(encoded_cookie_key).encrypt({"value": object()}, aad="user:123")


def test_pairing_token_hash_and_verify() -> None:
    token = generate_pairing_token()
    stored_hash = hash_pairing_token(token)

    assert len(token) >= 43
    assert len(stored_hash) == 64
    assert verify_pairing_token(token, stored_hash) is True
    assert verify_pairing_token(generate_pairing_token(), stored_hash) is False
    assert verify_pairing_token(token, "malformed") is False


def test_pairing_tokens_are_unique() -> None:
    assert generate_pairing_token() != generate_pairing_token()


def test_invite_password_accepts_match_and_rejects_mismatch() -> None:
    encoded_hash = PasswordHasher(time_cost=1, memory_cost=1024).hash("friend-passcode")
    verifier = InvitePassword(encoded_hash)

    assert verifier.verify("friend-passcode") is True
    assert verifier.verify("wrong-passcode") is False


def test_invite_password_fails_closed_for_invalid_hash() -> None:
    assert InvitePassword("not-an-argon2-hash").verify("friend-passcode") is False


def test_app_session_round_trip_and_default_lifetime() -> None:
    signer = AppSessionSigner("a sufficiently private app secret")
    token = signer.issue("friend-user", "generation-one")

    session = signer.verify(token)

    assert session.user_id == "friend-user"
    assert session.session_generation == "generation-one"
    assert APP_SESSION_MAX_AGE_SECONDS == 7 * 24 * 60 * 60
    assert "friend-user" not in token
    assert "generation-one" not in token


def test_app_session_generation_is_signed_and_distinguishes_session_tokens() -> None:
    signer = AppSessionSigner("a sufficiently private app secret")

    first = signer.issue("friend-user", "generation-one")
    rotated = signer.issue("friend-user", "generation-two")

    assert first != rotated
    assert signer.verify(first).session_generation == "generation-one"
    assert signer.verify(rotated).session_generation == "generation-two"


@pytest.mark.parametrize("generation", ["", None, 0])
def test_app_session_requires_a_nonempty_session_generation(generation) -> None:
    with pytest.raises(ValueError, match="Session generation"):
        AppSessionSigner("app secret").issue("friend-user", generation)


def test_app_session_rejects_wrong_secret() -> None:
    token = AppSessionSigner("first secret").issue("friend-user", "generation-one")

    with pytest.raises(SessionTokenError):
        AppSessionSigner("second secret").verify(token)


@pytest.mark.parametrize("token", ["", "not-a-token", "a.b.c"])
def test_app_session_rejects_malformed_token(token) -> None:
    with pytest.raises(SessionTokenError):
        AppSessionSigner("app secret").verify(token)


def test_app_session_rejects_tampering() -> None:
    signer = AppSessionSigner("app secret")
    token = signer.issue("friend-user", "generation-one")
    token_parts = token.split(".")
    replacement = "A" if token_parts[-1][0] != "A" else "B"
    token_parts[-1] = replacement + token_parts[-1][1:]

    with pytest.raises(SessionTokenError):
        signer.verify(".".join(token_parts))


def test_app_session_rejects_expired_token() -> None:
    token = AppSessionSigner("app secret").issue("friend-user", "generation-one")
    expired_signer = AppSessionSigner("app secret", max_age_seconds=-1)

    with pytest.raises(SessionTokenExpired):
        expired_signer.verify(token)
