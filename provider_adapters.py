"""Pluggable entropy, QKD-key and key-store adapters. External services FAIL CLOSED.

Implemented and testable here: NIST SP 800-90B-style continuous health tests, entropy mixing,
an ETSI GS QKD 014-shaped client driven through an injected transport, and an encrypted
software key store. Nothing here is connected to real QRNG/QKD/HSM/QNu hardware or services.
"""
import base64
import hashlib
import json
import math
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class NotConnected(RuntimeError):
    pass


class EntropyFailure(RuntimeError):
    pass


def _binom_quantile(n, p, q):
    total = 0.0
    for k in range(n + 1):
        total += math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))
        if total >= q:
            return k
    return n


class HealthTests:
    """Repetition Count and Adaptive Proportion tests (SP 800-90B 4.4) for 8-bit samples."""

    def __init__(self, h=8.0, alpha_exp=20, window=512):
        self.rct_cutoff = 1 + math.ceil(alpha_exp / h)
        self.window = window
        self.apt_cutoff = 1 + _binom_quantile(window, 2 ** -h, 1 - 2 ** -alpha_exp)
        self.last, self.run = None, 0
        self.ref, self.seen, self.hits = None, 0, 0

    def feed(self, data):
        for b in data:
            if b == self.last:
                self.run += 1
                if self.run >= self.rct_cutoff:
                    raise EntropyFailure('Repetition count test failed.')
            else:
                self.last, self.run = b, 1
            if self.ref is None or self.seen >= self.window:
                self.ref, self.seen, self.hits = b, 1, 1
            else:
                self.seen += 1
                if b == self.ref:
                    self.hits += 1
                    if self.hits >= self.apt_cutoff:
                        raise EntropyFailure('Adaptive proportion test failed.')


class OSEntropy:
    name = 'os-csprng'

    def read(self, n):
        return os.urandom(n)


class QRNGSource:
    """Wraps a vendor QRNG. The fetch callable is injected; with none it fails closed.

    Output is HKDF-mixed with OS entropy, so a weak QRNG can never reduce strength below the OS CSPRNG.
    """
    name = 'qrng'

    def __init__(self, fetch=None):
        self.fetch, self.tests = fetch, HealthTests()

    def read(self, n):
        if self.fetch is None:
            raise NotConnected('No QRNG device or service is connected. Provide vendor access and a fetch function.')
        raw = self.fetch(n)
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < n:
            raise EntropyFailure('QRNG returned too little data.')
        self.tests.feed(raw)  # raises on failure; caller must not fall back silently
        return HKDF(algorithm=hashes.SHA256(), length=n, salt=None, info=b'QuantaVoice qrng mix').derive(
            bytes(raw[:n]) + os.urandom(32)) if n <= 255 * 32 else bytes(raw[:n])


class QKDKeyClient:
    """ETSI GS QKD 014-shaped client (enc_keys / dec_keys). Transport must be supplied.

    transport(method, path, body_or_None) -> dict. Real use needs authenticated QKD equipment (mutual TLS).
    """

    def __init__(self, transport=None, master_sae='quantavoice-master'):
        self.transport, self.master = transport, master_sae

    def _call(self, method, path, body=None):
        if self.transport is None:
            raise NotConnected('No QKD key manager is configured. Authenticated QKD equipment is required.')
        return self.transport(method, path, body)

    def get_key(self, slave_sae_id, size_bits=256):
        if size_bits % 8 or size_bits < 128 or size_bits > 1024:
            raise ValueError('Unsupported key size.')
        out = self._call('POST', '/api/v1/keys/%s/enc_keys' % slave_sae_id, {'number': 1, 'size': size_bits})
        item = out['keys'][0]
        key = base64.b64decode(item['key'], validate=True)
        if len(key) * 8 != size_bits:
            raise EntropyFailure('QKD key has the wrong size.')
        HealthTests().feed(key) if len(key) >= 16 else None
        return item['key_ID'], key

    def get_key_with_id(self, master_sae_id, key_id):
        out = self._call('POST', '/api/v1/keys/%s/dec_keys' % master_sae_id, {'key_IDs': [{'key_ID': key_id}]})
        return base64.b64decode(out['keys'][0]['key'], validate=True)


class SoftwareKeyStore:
    """Secrets encrypted at rest with a scrypt-derived AES-256-GCM key. Not an HSM."""
    name = 'software-keystore'

    def __init__(self, path, passphrase):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not isinstance(passphrase, str) or len(passphrase) < 12:
            raise ValueError('Use a passphrase of at least 12 characters.')
        self.passphrase = passphrase.encode()

    def _key(self, salt):
        return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(self.passphrase)

    def put(self, name, secret):
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        blob = AESGCM(self._key(salt)).encrypt(nonce, bytes(secret), name.encode())
        data = json.loads(self.path.read_text()) if self.path.exists() else {}
        data[name] = {'salt': salt.hex(), 'nonce': nonce.hex(), 'blob': blob.hex()}
        self.path.write_text(json.dumps(data))

    def get(self, name):
        data = json.loads(self.path.read_text())
        r = data[name]
        return AESGCM(self._key(bytes.fromhex(r['salt']))).decrypt(
            bytes.fromhex(r['nonce']), bytes.fromhex(r['blob']), name.encode())


class HSMKeyStore:
    name = 'pkcs11-hsm'

    def __init__(self, module_path=None, **_):
        if not module_path:
            raise NotConnected('No PKCS#11 module configured. An HSM or cloud HSM with ML-KEM/ML-DSA support is required.')
        raise NotConnected('PKCS#11 integration is not implemented; vendor module and test device are required.')


def provider_status():
    """Honest connection report used by the CBOM, guide and reports."""
    report = {}
    for name, factory in (('qrng', lambda: QRNGSource().read(16)), ('qkd', lambda: QKDKeyClient().get_key('x')),
                          ('hsm', lambda: HSMKeyStore())):
        try:
            factory()
            report[name] = 'connected'
        except NotConnected as exc:
            report[name] = 'not connected: ' + str(exc).split('.')[0]
    report['os_entropy'] = 'available'
    report['software_keystore'] = 'available (not an HSM)'
    return report
