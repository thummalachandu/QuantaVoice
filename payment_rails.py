"""Payment-rail adapters: UPI payment-intent URIs, a no-network sandbox rail and SHADOW MODE.

Shadow mode records what voice authorization WOULD have decided next to the real rail's decision
so a bank can measure agreement without any change to money movement. No real rail is connected.
"""
import re
from decimal import Decimal, InvalidOperation
from urllib.parse import parse_qs, quote, urlparse

VPA = re.compile(r'[A-Za-z0-9._-]{2,64}@[A-Za-z][A-Za-z0-9]{1,31}')


def validate_vpa(vpa):
    if not isinstance(vpa, str) or not VPA.fullmatch(vpa):
        raise ValueError('Invalid UPI address (VPA).')
    return vpa


def build_upi_uri(vpa, name, rupees, note='', ref=''):
    validate_vpa(vpa)
    try:
        amount = Decimal(str(rupees))
        if not amount.is_finite() or amount <= 0 or amount > 100000 or amount != amount.quantize(Decimal('0.01')):
            raise ValueError
    except (InvalidOperation, ValueError):
        raise ValueError('Use a positive amount up to 1,00,000 INR with at most two decimals.')
    if not name or len(name) > 60 or len(note) > 80 or len(ref) > 35 or any(ord(c) < 32 for c in name + note + ref):
        raise ValueError('Invalid name, note or reference.')
    parts = [('pa', vpa), ('pn', name), ('am', format(amount, '.2f')), ('cu', 'INR')]
    if note:
        parts.append(('tn', note))
    if ref:
        parts.append(('tr', ref))
    return 'upi://pay?' + '&'.join('%s=%s' % (k, quote(v, safe='@')) for k, v in parts)


def parse_upi_uri(uri):
    u = urlparse(uri)
    if u.scheme != 'upi' or u.netloc != 'pay':
        raise ValueError('Not a UPI pay URI.')
    q = {k: v[0] for k, v in parse_qs(u.query, strict_parsing=True).items()}
    if set(q) - {'pa', 'pn', 'am', 'cu', 'tn', 'tr'} or q.get('cu') != 'INR' or not {'pa', 'pn', 'am'} <= set(q):
        raise ValueError('Unexpected or missing UPI fields.')
    validate_vpa(q['pa'])
    return q


class SandboxRail:
    """Deterministic fake rail. Never opens a network connection or moves money."""
    name = 'upi-sandbox'

    def __init__(self, balance_paise=5000000):
        self.balance, self.seen = balance_paise, set()

    def submit(self, uri, reference):
        q = parse_upi_uri(uri)
        if reference in self.seen:
            return {'status': 'duplicate', 'reference': reference}
        paise = int(Decimal(q['am']) * 100)
        if paise > self.balance:
            return {'status': 'failed', 'reason': 'insufficient sandbox balance', 'reference': reference}
        self.seen.add(reference)
        self.balance -= paise
        return {'status': 'success', 'reference': reference, 'simulated': True}


class ShadowRail:
    """Compare voice-authorization decisions with the legacy rail's decisions."""

    def __init__(self, audit=None):
        self.rows, self.audit = [], audit

    def observe(self, reference, voice_action, legacy_action):
        for a in (voice_action, legacy_action):
            if a not in ('allow', 'step_up', 'deny'):
                raise ValueError('Unknown action.')
        row = {'reference': reference, 'voice': voice_action, 'legacy': legacy_action}
        self.rows.append(row)
        if self.audit:
            self.audit.append('shadow.observed', row)
        return row

    def metrics(self):
        n = len(self.rows)
        if not n:
            return {'n': 0}
        agree = sum(r['voice'] == r['legacy'] for r in self.rows)
        return {'n': n, 'agreement': agree / n,
                'voice_would_block_legacy_allowed': sum(r['voice'] != 'allow' and r['legacy'] == 'allow' for r in self.rows),
                'voice_would_allow_legacy_blocked': sum(r['voice'] == 'allow' and r['legacy'] != 'allow' for r in self.rows)}
