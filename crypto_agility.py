"""Crypto-agility: ordered algorithm policy with downgrade protection.

Classical-only suites are rejected outright. The client's offer is hashed into the key derivation
context so a man-in-the-middle that edits the offer produces keys that no longer match.
"""
import hashlib
import json

SUITES = {
    'hybrid-x25519-mlkem768+mldsa65+aes256gcm': {'kem': 'X25519+ML-KEM-768', 'sig': 'ML-DSA-65', 'aead': 'AES-256-GCM', 'pq': True},
    'mlkem768+mldsa65+aes256gcm': {'kem': 'ML-KEM-768', 'sig': 'ML-DSA-65', 'aead': 'AES-256-GCM', 'pq': True},
    'x25519+ed25519+aes256gcm': {'kem': 'X25519', 'sig': 'Ed25519', 'aead': 'AES-256-GCM', 'pq': False},
}
DEFAULT_POLICY = ['hybrid-x25519-mlkem768+mldsa65+aes256gcm', 'mlkem768+mldsa65+aes256gcm']


def offer_binding(offer):
    return hashlib.sha256(json.dumps(list(offer), separators=(',', ':')).encode()).digest()


def negotiate(client_offer, server_policy=None):
    """Server picks its most-preferred suite that the client offered and that is post-quantum."""
    policy = server_policy or DEFAULT_POLICY
    for name in policy:
        if name not in SUITES or not SUITES[name]['pq']:
            raise ValueError('Policy may contain only known post-quantum suites.')
    for name in policy:
        if name in client_offer:
            return name, offer_binding(client_offer)
    raise ValueError('No acceptable post-quantum suite offered; classical-only is refused.')


def check_binding(client_offer, chosen, binding):
    """The client re-computes the binding from what it actually sent; mismatch means tampering."""
    return binding == offer_binding(client_offer) and chosen in client_offer
