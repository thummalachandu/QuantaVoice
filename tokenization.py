"""Simulated payment-token vault: raw card numbers are never handed to the voice layer.

Tokens are random Luhn-valid numbers (prefix 9, a reserved test range) mapped to an
AES-256-GCM-encrypted PAN, domain-restricted to one merchant (and optionally one device).
Each payment gets a single-use cryptogram bound to the exact intent digest.
Use TEST card numbers only. This is a design demonstrator, not PCI DSS certified.
"""
import hashlib
import hmac
import secrets
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def luhn_valid(number):
    if not number.isdigit() or not 12 <= len(number) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def luhn_check_digit(partial):
    for d in range(10):
        if luhn_valid(partial + str(d)):
            return str(d)


def mask(pan):
    return '*' * (len(pan) - 4) + pan[-4:]


class TokenVault:
    def __init__(self, key=None):
        self.key = key or AESGCM.generate_key(256)
        if len(self.key) != 32:
            raise ValueError('Vault key must be 32 bytes.')
        self.mac_key = hashlib.sha256(b'cryptogram' + self.key).digest()
        self.lock = threading.Lock()
        self.records, self.used = {}, set()

    def tokenize(self, pan, merchant_id, device_id=None):
        pan = pan.replace(' ', '')
        if not luhn_valid(pan):
            raise ValueError('Card number failed validation.')
        with self.lock:
            while True:
                body = '9' + ''.join(str(secrets.randbelow(10)) for _ in range(14))
                token = body + luhn_check_digit(body)
                if token not in self.records:
                    break
            nonce = secrets.token_bytes(12)
            blob = AESGCM(self.key).encrypt(nonce, pan.encode(), token.encode())
            self.records[token] = {'nonce': nonce, 'blob': blob, 'merchant': merchant_id,
                                   'device': device_id, 'last4': pan[-4:], 'counter': 0, 'active': True}
        return token

    def info(self, token):
        r = self.records.get(token)
        return None if not r else {'merchant': r['merchant'], 'device': r['device'], 'last4': r['last4'],
                                   'active': r['active']}

    def revoke(self, token):
        with self.lock:
            if token in self.records:
                self.records[token]['active'] = False

    def cryptogram(self, token, merchant_id, digest, device_id=None):
        """Single-use authorization cryptogram for exactly one intent digest."""
        with self.lock:
            r = self.records.get(token)
            if not r or not r['active'] or r['merchant'] != merchant_id or r['device'] != device_id:
                raise PermissionError('Token not valid for this domain.')
            r['counter'] += 1
            msg = ('%s|%s|%s|%d' % (token, merchant_id, digest, r['counter'])).encode()
            return {'counter': r['counter'], 'cryptogram': hmac.new(self.mac_key, msg, hashlib.sha256).hexdigest()}

    def verify_cryptogram(self, token, merchant_id, digest, counter, value):
        with self.lock:
            r = self.records.get(token)
            if not r or not r['active'] or r['merchant'] != merchant_id or (token, counter) in self.used:
                return False
            msg = ('%s|%s|%s|%d' % (token, merchant_id, digest, counter)).encode()
            if not hmac.compare_digest(hmac.new(self.mac_key, msg, hashlib.sha256).hexdigest(), value):
                return False
            self.used.add((token, counter))
            return True

    def detokenize(self, token, merchant_id, device_id=None):
        """Returns the PAN only inside the vault trust boundary (processor side)."""
        with self.lock:
            r = self.records.get(token)
            if not r or not r['active'] or r['merchant'] != merchant_id or r['device'] != device_id:
                raise PermissionError('Token not valid for this domain.')
            return AESGCM(self.key).decrypt(r['nonce'], r['blob'], token.encode()).decode()
