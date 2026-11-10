"""Local cryptography demonstration. Not biometric authentication or banking."""
import json
import secrets
import time
import threading
import hashlib
from functools import wraps
from pqcrypto.sign.ml_dsa_65 import generate_keypair as signature_keypair, sign, verify
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CONTEXT = b'QuantaVoice signed local demonstration v5'

def synchronized(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)
    return wrapped

def key(secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=CONTEXT).derive(secret)

@dataclass(frozen=True)
class Packet:
    kem: bytes
    nonce: bytes
    payload: bytes
    signature: bytes = b''

class Lab:
    def __init__(self):
        self._lock = threading.RLock()
        self.public, self.private = generate_keypair()
        self.sign_public, self.sign_private = signature_keypair()
        self.session = secrets.token_hex(16)
        self.key_created = time.time()
        self.balance = 5000000  # paise, simulated only
        self.pending = {}

    @synchronized
    def rotate_keys(self):
        # Generate all replacements before invalidating the active key pair.
        public, private = generate_keypair()
        sign_public, sign_private = signature_keypair()
        self.pending.clear()
        self.public, self.private = public, private
        self.sign_public, self.sign_private = sign_public, sign_private
        self.session = secrets.token_hex(16)
        self.key_created = time.time()
        return self.key_id()

    def key_id(self):
        return hashlib.sha256(self.public + self.sign_public).hexdigest()

    @synchronized
    def prepare(self, recipient, rupees, contact_id=None, note=""):
        from contacts import resolve
        contact = resolve(contact_id) if contact_id is not None else None
        if contact and contact.name != recipient.strip():
            raise ValueError("Recipient does not match the selected account.")
        note = note.strip()
        if len(note)>140 or any(ord(c)<32 for c in note):
            raise ValueError("Payment note must be a single line of at most 140 characters.")
        recipient = recipient.strip()
        if not recipient or len(recipient) > 60:
            raise ValueError('Enter a recipient between 1 and 60 characters.')
        try:
            amount = Decimal(str(rupees))
            if not amount.is_finite() or amount <= 0 or amount > 50000 or amount * 100 != (amount * 100).to_integral_value():
                raise ValueError('Use a positive amount up to 50,000 with at most two decimals.')
        except InvalidOperation as exc:
            raise ValueError('Enter a numeric amount.') from exc
        paise = int(amount * 100)
        if paise > self.balance:
            raise ValueError('Insufficient simulated balance.')
        self.pending.clear()  # only one active intent in this single-user lab
        intent = {'id': secrets.token_hex(16), 'recipient': recipient, 'paise': paise}
        if contact:
            intent.update(contact_id=contact.id, payment_id=contact.payment_id, phone=contact.phone)
        intent['note'] = note
        intent.update(session=self.session, key_id=self.key_id(), created=time.time())
        raw = json.dumps(intent, sort_keys=True).encode()
        start = time.perf_counter()
        signature = sign(self.sign_private, CONTEXT + raw)
        kem, sender_secret = encrypt(self.public)
        nonce = secrets.token_bytes(12)
        payload = AESGCM(key(sender_secret)).encrypt(nonce, raw, CONTEXT)
        self.pending[intent['id']] = (raw, time.monotonic() + 120)
        return Packet(kem, nonce, payload, signature), intent, (time.perf_counter()-start)*1000

    @synchronized
    def confirm(self, packet):
        secret = decrypt(self.private, packet.kem)
        raw = AESGCM(key(secret)).decrypt(packet.nonce, packet.payload, CONTEXT)
        if not verify(self.sign_public, CONTEXT + raw, packet.signature):
            raise ValueError('ML-DSA signature verification failed.')
        intent = json.loads(raw)
        if intent.get('session') != self.session or intent.get('key_id') != self.key_id():
            raise ValueError('Wrong session or signing key.')
        saved = self.pending.get(intent['id'])
        if not saved or saved[0] != raw or time.monotonic() > saved[1]:
            raise ValueError('Unknown, expired, or already consumed transaction.')
        if intent['paise'] > self.balance:
            raise ValueError('Insufficient simulated balance.')
        del self.pending[intent['id']]
        self.balance -= intent['paise']
        return intent

def tampered(packet):
    changed = bytearray(packet.payload)
    changed[0] ^= 1
    return Packet(packet.kem, packet.nonce, bytes(changed), packet.signature)
