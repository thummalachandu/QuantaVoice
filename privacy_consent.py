"""Biometric privacy controls: consent ledger, purpose limitation, retention, erasure, encrypted voiceprints.

Why: a voiceprint is biometric personal data (India DPDP Act 2023, EU GDPR Art. 9, Australia Privacy Act).
Banks and telcos ask for consent, purpose limitation, retention limits and a deletion path before any pilot.

What this gives you
  * ConsentLedger : per-subject, per-purpose consent with expiry and withdrawal, kept as an append-only history.
  * TemplateVault : voiceprint embeddings encrypted with AES-256-GCM under a per-subject key (HKDF from a master key),
                    released only while consent for the purpose is valid. Erase = delete ciphertext (crypto-erase).
  * Subject ids are pseudonymised with HMAC-SHA256, so the database never holds the raw customer identifier.

What it does NOT give you
  * It is not a legal opinion or a compliance certificate. Notice text, lawful basis and retention periods are the
    controller's decision.
  * The master key lives in process memory unless you pass one in. Production needs an HSM/KMS.
  * Backups, logs and copies outside this database are not erased by erase().
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PURPOSES = ('voice_verification', 'anti_spoofing', 'audit_evidence')
DAY = 86400.0


class ConsentError(Exception):
    pass


def _subject(master: bytes, raw_id: str) -> str:
    if not raw_id or len(raw_id) > 256:
        raise ValueError('Invalid subject id.')
    return hmac.new(master, b'subject|' + raw_id.encode(), hashlib.sha256).hexdigest()


class ConsentLedger:
    def __init__(self, path, master_key: bytes | None = None, clock=time.time):
        self.master = master_key or secrets.token_bytes(32)
        if len(self.master) != 32:
            raise ValueError('master_key must be 32 bytes.')
        self.clock, self.lock = clock, threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS consent(id INTEGER PRIMARY KEY, subject TEXT NOT NULL, '
                        'purpose TEXT NOT NULL, notice_version TEXT NOT NULL, granted REAL NOT NULL, '
                        'expires REAL NOT NULL, withdrawn REAL)')
        self.db.commit()

    def subject(self, raw_id: str) -> str:
        return _subject(self.master, raw_id)

    def grant(self, raw_id: str, purpose: str, notice_version: str, ttl_days: float = 365) -> None:
        if purpose not in PURPOSES:
            raise ConsentError('Unknown purpose.')
        if not 0 < ttl_days <= 3650:
            raise ValueError('ttl_days out of range.')
        now = self.clock()
        with self.lock:
            self.db.execute('INSERT INTO consent(subject,purpose,notice_version,granted,expires) VALUES(?,?,?,?,?)',
                            (self.subject(raw_id), purpose, notice_version, now, now + ttl_days * DAY))
            self.db.commit()

    def withdraw(self, raw_id: str, purpose: str | None = None) -> int:
        now, sub = self.clock(), self.subject(raw_id)
        with self.lock:
            sql = 'UPDATE consent SET withdrawn=? WHERE subject=? AND withdrawn IS NULL'
            args = [now, sub]
            if purpose:
                sql, args = sql + ' AND purpose=?', args + [purpose]
            n = self.db.execute(sql, args).rowcount
            self.db.commit()
            return n

    def allowed(self, raw_id: str, purpose: str) -> bool:
        row = self.db.execute('SELECT 1 FROM consent WHERE subject=? AND purpose=? AND withdrawn IS NULL AND expires>? '
                              'LIMIT 1', (self.subject(raw_id), purpose, self.clock())).fetchone()
        return row is not None

    def history(self, raw_id: str) -> list[dict]:
        """Data-subject access: consent history only, never biometric content."""
        rows = self.db.execute('SELECT purpose,notice_version,granted,expires,withdrawn FROM consent '
                               'WHERE subject=? ORDER BY id', (self.subject(raw_id),)).fetchall()
        return [dict(zip(('purpose', 'notice_version', 'granted', 'expires', 'withdrawn'), r)) for r in rows]

    def close(self):
        self.db.close()


class TemplateVault:
    """Encrypted voiceprint store gated by consent."""

    def __init__(self, path, ledger: ConsentLedger, retention_days: float = 365, clock=time.time):
        if not 0 < retention_days <= 3650:
            raise ValueError('retention_days out of range.')
        self.ledger, self.retention, self.clock = ledger, retention_days * DAY, clock
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS template(subject TEXT PRIMARY KEY, nonce BLOB NOT NULL, '
                        'blob BLOB NOT NULL, created REAL NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS erasure(subject_hash TEXT NOT NULL, erased REAL NOT NULL, '
                        'reason TEXT NOT NULL)')
        self.db.commit()

    def _aead(self, sub: str) -> tuple[AESGCM, bytes]:
        key = HKDF(hashes.SHA256(), 32, salt=None, info=b'QuantaVoice template key v1|' + sub.encode()).derive(
            self.ledger.master)
        return AESGCM(key), b'QuantaVoice template v1|' + sub.encode()

    def store(self, raw_id: str, embedding: bytes) -> None:
        if not embedding or len(embedding) > 65536:
            raise ValueError('Invalid embedding.')
        if not self.ledger.allowed(raw_id, 'voice_verification'):
            raise ConsentError('No valid consent for voice_verification.')
        sub = self.ledger.subject(raw_id)
        aead, aad = self._aead(sub)
        nonce = secrets.token_bytes(12)
        with self.lock:
            self.db.execute('INSERT OR REPLACE INTO template VALUES(?,?,?,?)',
                            (sub, nonce, aead.encrypt(nonce, embedding, aad), self.clock()))
            self.db.commit()

    def load(self, raw_id: str, purpose: str = 'voice_verification') -> bytes:
        if not self.ledger.allowed(raw_id, purpose):
            raise ConsentError('Consent missing, expired or withdrawn.')
        sub = self.ledger.subject(raw_id)
        row = self.db.execute('SELECT nonce,blob,created FROM template WHERE subject=?', (sub,)).fetchone()
        if not row:
            raise KeyError('No template.')
        if self.clock() - row[2] >= self.retention:
            self.erase(raw_id, 'retention_expired')
            raise ConsentError('Retention period over; template erased.')
        aead, aad = self._aead(sub)
        try:
            return aead.decrypt(row[0], row[1], aad)
        except InvalidTag as exc:
            raise ConsentError('Template failed integrity check.') from exc

    def erase(self, raw_id: str, reason: str = 'subject_request') -> bool:
        sub = self.ledger.subject(raw_id)
        with self.lock:
            n = self.db.execute('DELETE FROM template WHERE subject=?', (sub,)).rowcount
            self.db.execute('INSERT INTO erasure VALUES(?,?,?)',
                            (hashlib.sha256(sub.encode()).hexdigest(), self.clock(), reason))
            self.db.commit()
        return n > 0

    def purge_expired(self) -> int:
        cutoff = self.clock() - self.retention
        with self.lock:
            subs = [r[0] for r in self.db.execute('SELECT subject FROM template WHERE created<=?', (cutoff,))]
            for s in subs:
                self.db.execute('DELETE FROM template WHERE subject=?', (s,))
                self.db.execute('INSERT INTO erasure VALUES(?,?,?)',
                                (hashlib.sha256(s.encode()).hexdigest(), self.clock(), 'retention_expired'))
            self.db.commit()
        return len(subs)

    def erasure_receipts(self) -> list[dict]:
        return [dict(zip(('subject_hash', 'erased', 'reason'), r))
                for r in self.db.execute('SELECT subject_hash,erased,reason FROM erasure ORDER BY rowid')]

    def close(self):
        self.db.close()
