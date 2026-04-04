"""
Static key storage for nodes.
Each node generates an X25519 keypair on first start and saves it to secure_tunnel_keys/.
"""
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

KEYS_DIR = Path(__file__).parent.parent / "secure_tunnel_keys"


def _key_paths(node_name: str):
    KEYS_DIR.mkdir(exist_ok=True)
    priv_path = KEYS_DIR / f"{node_name}.x25519.key"
    pub_path = KEYS_DIR / f"{node_name}.x25519.pub"
    return priv_path, pub_path


def load_or_generate(node_name: str):
    """Returns (private_key, public_key) for given node, generating if needed."""
    priv_path, pub_path = _key_paths(node_name)
    if priv_path.exists():
        priv_bytes = priv_path.read_bytes()
        priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    else:
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        priv_path.write_bytes(priv_bytes)
        # Restrict read permissions to owner only (Unix: 0o600)
        try:
            priv_path.chmod(0o600)
        except NotImplementedError:
            pass  # Windows — permissions managed via ACL, not chmod
        pub = priv.public_key()
        pub_path.write_bytes(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
    pub = priv.public_key()
    return priv, pub


def load_public(node_name: str) -> X25519PublicKey:
    """Load only the public key for a node (must exist)."""
    _, pub_path = _key_paths(node_name)
    return X25519PublicKey.from_public_bytes(pub_path.read_bytes())
