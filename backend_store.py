"""Loopback research authorization service. Every debit is simulated.

The operator console is a trusted demo boundary, not a bank identity verifier.
The SQLite file is local plaintext metadata, not a tamper-proof audit store.
"""
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt
from pqcrypto.sign.ml_dsa_65 import generate_keypair as sig_keypair, sign, verify
from core import CONTEXT, Packet, key
import hybrid_kex


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


class LocalPQCProvider:
    name = 'local-pqcrypto (QNu not connected)'

    def __init__(self):
        self.public, self.private = generate_keypair()
        self.sign_public, self.sign_private = sig_keypair()
        self.fingerprint = hashlib.sha256(self.public + self.sign_public).hexdigest()

    def seal(self, raw):
        kem, secret = encrypt(self.public)
        nonce = secrets.token_bytes(12)
        return Packet(kem, nonce, AESGCM(key(secret)).encrypt(nonce, raw, CONTEXT),
                      sign(self.sign_private, CONTEXT + raw))

    def open(self, packet):
        raw = AESGCM(key(decrypt(self.private, packet.kem))).decrypt(
            packet.nonce, packet.payload, CONTEXT)
        if not verify(self.sign_public, CONTEXT + raw, packet.signature):
            raise ValueError('Signature verification failed.')
        return raw


class HybridPQCProvider:
    """X25519 + ML-KEM-768 hybrid key establishment, AES-256-GCM, ML-DSA-65 signature."""
    name = 'local-hybrid-x25519-mlkem768 (QNu not connected)'

    def __init__(self):
        self.hpub, self.hpriv = hybrid_kex.generate()
        self.sign_public, self.sign_private = sig_keypair()
        self.fingerprint = hashlib.sha256(self.hpub.x25519 + self.hpub.mlkem + self.sign_public).hexdigest()

    def seal(self, raw):
        ct, secret = hybrid_kex.encapsulate(self.hpub, CONTEXT)
        nonce = secrets.token_bytes(12)
        return Packet(ct, nonce, AESGCM(key(secret)).encrypt(nonce, raw, CONTEXT),
                      sign(self.sign_private, CONTEXT + raw))

    def open(self, packet):
        secret = hybrid_kex.decapsulate(self.hpub, self.hpriv, packet.kem, CONTEXT)
        raw = AESGCM(key(secret)).decrypt(packet.nonce, packet.payload, CONTEXT)
        if not verify(self.sign_public, CONTEXT + raw, packet.signature):
            raise ValueError('Signature verification failed.')
        return raw


def provider_for(name):
    if name == 'local':
        return LocalPQCProvider()
    if name == 'hybrid':
        return HybridPQCProvider()
    if name == 'qnu':
        raise RuntimeError('QNu is NOT integrated. Obtain the official SDK, credentials, '
                           'documentation and sandbox before implementing a reviewed provider.')
    raise ValueError('Unknown crypto provider.')


class BackendStore:
    def __init__(self, path, *, demo=False, clock=time.time, provider='local'):
        self.lock = threading.RLock()
        self.clock = clock
        self.demo = demo
        self.crypto = provider_for(provider)
        self.bootstrap_token = secrets.token_urlsafe(32)
        self.sessions = {}
        self.packets = {}
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA busy_timeout=5000')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS account(id INTEGER PRIMARY KEY CHECK(id=1), balance INTEGER NOT NULL);
          INSERT OR IGNORE INTO account VALUES(1,5000000);
          CREATE TABLE IF NOT EXISTS transactions(
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, raw TEXT NOT NULL,
            digest TEXT NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL,
            amount INTEGER NOT NULL, consumed REAL);
        ''')
        # Ephemeral keys/session capabilities never resume after a process restart.
        self.db.execute("UPDATE transactions SET status='cancelled' WHERE status IN ('pending','approved')")

    def close(self):
        with self.lock:
            self.db.close()

    def session(self, token):
        with self.lock:
            if not isinstance(token, str) or not hmac.compare_digest(token, self.bootstrap_token):
                raise PermissionError('Invalid launch capability.')
            now = self.clock()
            self.sessions = {k: v for k, v in self.sessions.items() if v[1] > now}
            if len(self.sessions) >= 32:
                raise ValueError('Session limit reached. Restart the lab.')
            secret = secrets.token_urlsafe(32)
            owner = secrets.token_hex(16)
            self.sessions[hashlib.sha256(secret.encode()).hexdigest()] = (owner, now + 1800)
            return {'token': secret, 'expires': now + 1800, 'key_fingerprint': self.crypto.fingerprint,
                    'provider': self.crypto.name, 'simulated': True}

    def owner(self, token):
        if not isinstance(token, str):
            raise PermissionError('Missing session.')
        entry = self.sessions.get(hashlib.sha256(token.encode()).hexdigest())
        if not entry or self.clock() >= entry[1]:
            raise PermissionError('Session expired or invalid. Relaunch the client.')
        return entry[0]

    def status(self, token):
        with self.lock:
            self.owner(token)
            return {'balance_paise': self.db.execute('SELECT balance FROM account WHERE id=1').fetchone()[0],
                    'key_fingerprint': self.crypto.fingerprint, 'simulated': True,
                    'real_identity_verifiers': False, 'qnu_connected': False}

    def prepare(self, token, body):
        with self.lock:
            owner = self.owner(token)
            if not isinstance(body, dict) or set(body) != {'recipient', 'destination', 'rupees', 'note'}:
                raise ValueError('Submit only recipient, destination, rupees and note. Client approval flags are forbidden.')
            if not all(isinstance(v, str) for v in body.values()):
                raise ValueError('Payment fields must be text.')
            recipient, dest, note = body['recipient'].strip(), body['destination'].strip(), body['note'].strip()
            if not 1 <= len(recipient) <= 60 or any(ord(c) < 32 for c in recipient):
                raise ValueError('Recipient must be a single line of 1–60 characters.')
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}@demo', dest):
                raise ValueError('This lab accepts demo destinations only, such as chandu@demo.')
            if len(note) > 140 or any(ord(c) < 32 for c in note):
                raise ValueError('Note must be one line, at most 140 characters.')
            try:
                value = Decimal(body['rupees'])
                if not value.is_finite() or value <= 0 or value > 50000 or value * 100 != (value * 100).to_integral_value():
                    raise ValueError('Use a positive amount up to ₹50,000 with at most two decimals.')
                paise = int(value * 100)
            except InvalidOperation as exc:
                raise ValueError('Invalid amount.') from exc
            now = self.clock()
            if paise > self.status(token)['balance_paise']:
                raise ValueError('Insufficient simulated balance.')
            count = self.db.execute("SELECT COUNT(*) FROM transactions WHERE status IN ('pending','approved') AND expires > ?", (now,)).fetchone()[0]
            if count >= 100:
                raise ValueError('Pending limit reached. Cancel or wait for expiry.')
            intent = {'id': secrets.token_hex(16), 'nonce': secrets.token_hex(16), 'owner': owner,
                      'recipient': recipient, 'destination': dest, 'paise': paise, 'currency': 'INR',
                      'note': note, 'created': now, 'expires': now + 120,
                      'key_fingerprint': self.crypto.fingerprint, 'simulation': True}
            raw = canonical(intent)
            packet = self.crypto.seal(raw)
            digest = hashlib.sha256(raw).hexdigest()
            # Replacing details cancels every outstanding approval for this session.
            old = self.db.execute("SELECT id FROM transactions WHERE owner=? AND status IN ('pending','approved')", (owner,)).fetchall()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute("UPDATE transactions SET status='cancelled' WHERE owner=? AND status IN ('pending','approved')", (owner,))
                self.db.execute('INSERT INTO transactions VALUES(?,?,?,?,?,?,?,NULL)',
                                (intent['id'], owner, raw.decode(), digest, intent['expires'], 'pending', paise))
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK')
                raise
            for item in old:
                self.packets.pop(item['id'], None)
            self.packets[intent['id']] = packet
            active_ids = {r[0] for r in self.db.execute("SELECT id FROM transactions WHERE status IN ('pending','approved') AND expires>?", (now,))}
            self.packets = {k: v for k, v in self.packets.items() if k in active_ids}
            return {'intent': intent, 'digest': digest, 'status': 'pending', 'simulated': True}

    def approve_from_console(self, transaction_id):
        """No HTTP route exposes this method. This is explicitly simulated review."""
        with self.lock:
            if not self.demo:
                raise PermissionError('Real verifiers are not integrated. Approval blocked. Use --demo-review for the lab.')
            row = self.db.execute('SELECT * FROM transactions WHERE id=?', (transaction_id,)).fetchone()
            if not row or row['status'] != 'pending' or self.clock() >= row['expires']:
                raise ValueError('Unknown, expired or inactive transaction.')
            self.db.execute("UPDATE transactions SET status='approved' WHERE id=?", (transaction_id,))
            return json.loads(row['raw'])

    def pending(self):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute(
                "SELECT raw FROM transactions WHERE status='pending' AND expires>? ORDER BY expires", (self.clock(),))]

    def confirm(self, token, body):
        with self.lock:
            owner = self.owner(token)
            if not isinstance(body, dict) or set(body) != {'id', 'digest'} or not all(isinstance(v, str) for v in body.values()):
                raise ValueError('Confirm requires exactly id and digest.')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row = self.db.execute('SELECT * FROM transactions WHERE id=?', (body['id'],)).fetchone()
                if not row or row['owner'] != owner or row['status'] != 'approved' or self.clock() >= row['expires']:
                    raise ValueError('Payment needs independent demo review, or is expired, cancelled or already consumed.')
                if not hmac.compare_digest(row['digest'], body['digest']):
                    raise ValueError('Reviewed details do not match. Submit and review again.')
                packet = self.packets.get(body['id'])
                if not packet:
                    raise ValueError('Crypto keys expired. Submit again.')
                raw = self.crypto.open(packet)
                if raw.decode() != row['raw'] or hashlib.sha256(raw).hexdigest() != row['digest']:
                    raise ValueError('Encrypted intent integrity failed.')
                now = self.clock()
                self.owner(token)  # Session must remain valid through crypto verification.
                if now >= row['expires']:
                    raise ValueError('Payment expired during verification.')
                changed = self.db.execute('UPDATE account SET balance=balance-? WHERE id=1 AND balance>=?',
                                          (row['amount'], row['amount'])).rowcount
                if changed != 1:
                    raise ValueError('Insufficient simulated balance.')
                self.db.execute("UPDATE transactions SET status='consumed',consumed=? WHERE id=?", (now, row['id']))
                balance = self.db.execute('SELECT balance FROM account WHERE id=1').fetchone()[0]
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK')
                raise
            self.packets.pop(body['id'], None)
            return {'receipt_id': row['id'], 'intent': json.loads(raw), 'balance_paise': balance,
                    'simulated': True, 'review': 'operator console demo only'}

    def rotate(self):
        with self.lock:
            replacement = type(self.crypto)()
            self.db.execute("UPDATE transactions SET status='cancelled' WHERE status IN ('pending','approved')")
            self.packets.clear()
            self.sessions.clear()
            self.crypto = replacement
            return replacement.fingerprint
