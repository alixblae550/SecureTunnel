"""
SecureTunnel cryptographic primitives.

Key exchange: Hybrid Forward Secrecy
    X25519  — classical ECDH  (PFS against current adversaries)
  + ML-KEM-768 (Kyber) — post-quantum KEM (PFS against future quantum computers)

  Both shared secrets are combined via HKDF so that compromising either one
  alone does not break the session.  The wire is safe even if quantum computers
  crack X25519 in the future, or if a flaw is found in Kyber.

Payload encryption: AES-256-GCM-SIV (nonce-misuse-resistant)
  SIV construction: even if a 96-bit nonce is reused, the attacker only learns
  that the same plaintext was sent twice — no key material is exposed.
  XChaCha20-Poly1305 (192-bit nonce) was preferred but requires OpenSSL >= 3.x
  bindings not yet exposed in the cryptography package.

ML-KEM availability:
    Requires `cryptography` >= 43.0.0.
    Falls back to X25519-only if ML-KEM is not available in the installed
    version — the system remains secure, just not post-quantum.
"""
import secrets as _secrets

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCMSIV
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── Post-quantum KEM availability ────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import (
        MLKEMPrivateKey,
        MLKEMParameters,
    )
    HAS_MLKEM = True
    _MLKEM_PARAMS = MLKEMParameters.ML_KEM_768   # 192-bit post-quantum security
except ImportError:
    print("[crypto] Post-quantum KEM unavailable, using X25519 (classical encryption)", flush=True)
    HAS_MLKEM = False
    MLKEMPrivateKey = None   # type: ignore[assignment,misc]
    _MLKEM_PARAMS = None


# ── Key derivation ────────────────────────────────────────────────────────────

def derive_session_key(
    x25519_shared: bytes,
    mlkem_shared: bytes | None = None,
    salt: bytes = b"secure_tunnel_v2",
) -> bytes:
    """
    Derive a 32-byte ChaCha20 session key from one or two shared secrets.

    If mlkem_shared is provided, the two secrets are concatenated before HKDF
    so the session key is only breakable if BOTH algorithms are compromised.
    """
    ikm = x25519_shared if mlkem_shared is None else (x25519_shared + mlkem_shared)
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=salt, info=b"session_key_v2")
    return hkdf.derive(ikm)


# ── ML-KEM helpers ────────────────────────────────────────────────────────────

def mlkem_generate():
    """
    Generate an ML-KEM-768 key pair.
    Returns (private_key, public_key_bytes) or (None, None) if unavailable.
    """
    if not HAS_MLKEM:
        return None, None
    priv = MLKEMPrivateKey.generate(_MLKEM_PARAMS)
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv, pub_bytes


def mlkem_encapsulate(pub_bytes: bytes):
    """
    Encapsulate to an ML-KEM-768 public key (server/responder side).
    Returns (ciphertext_bytes, shared_secret_bytes) or (None, None).
    """
    if not HAS_MLKEM or not pub_bytes:
        return None, None
    try:
        from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEMPublicKey
        pub = MLKEMPublicKey.from_public_bytes_raw(_MLKEM_PARAMS, pub_bytes)
        ct, ss = pub.encapsulate()
        return ct, ss
    except Exception:
        return None, None


def mlkem_decapsulate(priv, ciphertext: bytes) -> bytes | None:
    """
    Decapsulate an ML-KEM ciphertext (client/initiator side).
    Returns shared_secret_bytes or None on failure.
    """
    if not HAS_MLKEM or priv is None or not ciphertext:
        return None
    try:
        return priv.decapsulate(ciphertext)
    except Exception:
        return None


# ── Payload encryption ────────────────────────────────────────────────────────
# AES-256-GCM-SIV: nonce-misuse-resistant AEAD.
# Even if a random 96-bit nonce is accidentally reused, the SIV construction
# only reveals that the same plaintext was sent twice — the session key and
# all other plaintexts remain secure.  This is strictly stronger than plain
# AES-GCM or ChaCha20-Poly1305 which catastrophically fail on nonce reuse.

_NONCE_LEN = 12  # AES-GCM-SIV uses 96-bit nonces


def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-256-GCM-SIV. Returns nonce (12B) + ciphertext."""
    aead = AESGCMSIV(key)
    nonce = _secrets.token_bytes(_NONCE_LEN)
    return nonce + aead.encrypt(nonce, plaintext, None)


def decrypt_message(key: bytes, data: bytes) -> bytes:
    """Decrypt AES-256-GCM-SIV frame. Raises InvalidTag on authentication failure."""
    aead = AESGCMSIV(key)
    nonce, ciphertext = data[:_NONCE_LEN], data[_NONCE_LEN:]
    return aead.decrypt(nonce, ciphertext, None)
