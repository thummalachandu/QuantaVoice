"""Hybrid key establishment: X25519 + ML-KEM-768 combined with HKDF-SHA256.

The shared secret stays safe if EITHER primitive survives (classical now, post-quantum later).
This is an application-layer hybrid KEM in the spirit of the IETF X25519MLKEM768 group; it is
NOT a TLS implementation and is not interoperable with TLS stacks. Not FIPS 140-3 validated.
"""
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt

LABEL = b'QuantaVoice hybrid-kex v1 X25519+ML-KEM-768'
X_LEN = 32


@dataclass(frozen=True)
class HybridPublic:
    x25519: bytes
    mlkem: bytes

    def fingerprint(self):
        return hashlib.sha256(self.x25519 + self.mlkem).hexdigest()


@dataclass(frozen=True)
class HybridPrivate:
    x25519: bytes
    mlkem: bytes


def _raw_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def generate():
    x_priv = X25519PrivateKey.generate()
    m_pub, m_priv = generate_keypair()
    private = HybridPrivate(x_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                 serialization.NoEncryption()), m_priv)
    return HybridPublic(_raw_pub(x_priv), m_pub), private


def _combine(ss_x, ss_m, recipient_x, eph_x, m_pub, m_ct, context):
    transcript = hashlib.sha256(recipient_x + eph_x + m_pub + m_ct).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=LABEL + b'|' + context + b'|' + transcript).derive(ss_x + ss_m)


def encapsulate(public, context=b''):
    """Return (ciphertext bytes, 32-byte shared secret)."""
    if len(public.x25519) != X_LEN:
        raise ValueError('Invalid X25519 public key length.')
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_pub(eph)
    ss_x = eph.exchange(X25519PublicKey.from_public_bytes(public.x25519))  # rejects all-zero output
    m_ct, ss_m = encrypt(public.mlkem)
    return eph_pub + m_ct, _combine(ss_x, ss_m, public.x25519, eph_pub, public.mlkem, m_ct, context)


def decapsulate(public, private, ciphertext, context=b''):
    if len(ciphertext) <= X_LEN:
        raise ValueError('Hybrid ciphertext too short.')
    eph_pub, m_ct = ciphertext[:X_LEN], ciphertext[X_LEN:]
    ss_x = X25519PrivateKey.from_private_bytes(private.x25519).exchange(X25519PublicKey.from_public_bytes(eph_pub))
    ss_m = decrypt(private.mlkem, m_ct)
    return _combine(ss_x, ss_m, public.x25519, eph_pub, public.mlkem, m_ct, context)
