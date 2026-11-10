"""Tamper-evident audit log: SHA-256 hash chain, every entry signed with ML-DSA-65.

Detects edits, deletions in the middle, reordering and (with a saved checkpoint) truncation.
It does NOT stop an attacker who holds the signing key or who deletes the whole file, and the
signing key lives in process memory unless you supply one. Export formats suit a SIEM import.
"""
import hashlib
import json
import threading
import time
from pathlib import Path

from pqcrypto.sign.ml_dsa_65 import generate_keypair, sign, verify

CONTEXT = b'QuantaVoice audit entry v1'
GENESIS = '0' * 64
SECRET_WORDS = ('token', 'secret', 'password', 'pan', 'pin', 'otp', 'private', 'authorization')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def redact(value):
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if any(w == str(k).lower() or str(k).lower().endswith('_' + w) for w in SECRET_WORDS)
                    else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class AuditLog:
    def __init__(self, path, keypair=None, clock=time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.lock = threading.RLock()
        self.public, self.private = keypair or generate_keypair()
        self.head, self.count = GENESIS, 0
        if self.path.exists():
            ok, count, head, error = self._scan(self.public)
            if not ok:
                raise ValueError('Existing audit log failed verification: ' + error)
            self.head, self.count = head, count

    def append(self, event, data=None):
        with self.lock:
            body = {'seq': self.count + 1, 'ts': round(self.clock(), 3), 'event': str(event),
                    'data': redact(data or {}), 'prev': self.head}
            digest = hashlib.sha256(canonical(body)).hexdigest()
            entry = dict(body, hash=digest, sig=sign(self.private, CONTEXT + digest.encode()).hex())
            with self.path.open('a', encoding='utf-8') as f:
                f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + '\n')
                f.flush()
            self.head, self.count = digest, self.count + 1
            return entry

    def _entries(self):
        if not self.path.exists():
            return
        with self.path.open(encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def _scan(self, public):
        prev, count = GENESIS, 0
        try:
            for e in self._entries():
                body = {k: e[k] for k in ('seq', 'ts', 'event', 'data', 'prev')}
                if e['seq'] != count + 1 or e['prev'] != prev:
                    return False, count, prev, 'chain broken at entry %s' % e.get('seq')
                digest = hashlib.sha256(canonical(body)).hexdigest()
                if digest != e['hash']:
                    return False, count, prev, 'content changed at entry %s' % e['seq']
                if not verify(public, CONTEXT + digest.encode(), bytes.fromhex(e['sig'])):
                    return False, count, prev, 'bad signature at entry %s' % e['seq']
                prev, count = digest, count + 1
        except (KeyError, ValueError, TypeError) as exc:
            return False, count, prev, 'malformed entry: %s' % type(exc).__name__
        return True, count, prev, ''

    def verify(self, public=None, checkpoint=None):
        """Return (ok, entries, message). A saved checkpoint additionally detects truncation."""
        with self.lock:
            ok, count, head, error = self._scan(public or self.public)
            if not ok:
                return False, count, error
            if checkpoint:
                if not verify(public or self.public, CONTEXT + canonical(checkpoint['body']),
                              bytes.fromhex(checkpoint['sig'])):
                    return False, count, 'checkpoint signature invalid'
                if count < checkpoint['body']['count']:
                    return False, count, 'log truncated: fewer entries than checkpoint'
                if self.hash_at(checkpoint['body']['count']) != checkpoint['body']['head']:
                    return False, count, 'log history differs from checkpoint'
            return True, count, 'ok'

    def hash_at(self, n):
        if n == 0:
            return GENESIS
        for e in self._entries():
            if e['seq'] == n:
                return e['hash']
        return None

    def checkpoint(self):
        with self.lock:
            body = {'count': self.count, 'head': self.head, 'ts': round(self.clock(), 3)}
            return {'body': body, 'sig': sign(self.private, CONTEXT + canonical(body)).hex()}

    def export_jsonl(self):
        return [json.dumps(e, sort_keys=True) for e in self._entries()]

    def export_cef(self, vendor='QuantaVoice', product='VoiceAuth', version='16'):
        """ArcSight Common Event Format lines for SIEM ingestion."""
        def esc(s):
            return str(s).replace('\\', '\\\\').replace('|', '\\|').replace('=', '\\=').replace('\n', ' ')
        lines = []
        for e in self._entries():
            ext = ' '.join('%s=%s' % (esc(k), esc(v)) for k, v in sorted(e['data'].items())
                           if not isinstance(v, (dict, list)))
            sev = 8 if 'declin' in e['event'] or 'fail' in e['event'] or 'tamper' in e['event'] else 3
            lines.append('CEF:0|%s|%s|%s|%s|%s|%d|rt=%d seq=%d %s' % (
                vendor, product, version, esc(e['event']), esc(e['event']), sev, int(e['ts'] * 1000), e['seq'], ext))
        return lines
