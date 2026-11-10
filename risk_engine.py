"""Transparent rule-based fraud-risk scoring for voice-initiated payments.

Heuristic weights are NOT trained or calibrated on real fraud data; they make the decision
logic explicit and auditable. Missing voice evidence can never produce an 'allow' (fail closed).
"""
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class RiskDecision:
    score: int
    action: str               # allow | step_up | deny
    reasons: list = field(default_factory=list)
    missing_evidence: list = field(default_factory=list)

    def as_dict(self):
        return {'score': self.score, 'action': self.action, 'reasons': list(self.reasons),
                'missing_evidence': list(self.missing_evidence)}


class VelocityTracker:
    def __init__(self, clock=time.time):
        self.clock, self.lock = clock, threading.Lock()
        self.events = defaultdict(deque)

    def record(self, subject, paise):
        with self.lock:
            self.events[subject].append((self.clock(), paise))

    def window(self, subject, seconds):
        with self.lock:
            now, q = self.clock(), self.events[subject]
            while q and now - q[0][0] > 86400:
                q.popleft()
            recent = [p for t, p in q if now - t <= seconds]
            return len(recent), sum(recent)


class RiskEngine:
    """Thresholds are explicit and must be set from your own development data in production."""

    def __init__(self, asv_min=0.5, cm_min=0.5, step_up_at=35, deny_at=70, velocity=None):
        if not 0 <= step_up_at < deny_at <= 100:
            raise ValueError('Need 0 <= step_up_at < deny_at <= 100.')
        self.asv_min, self.cm_min = asv_min, cm_min
        self.step_up_at, self.deny_at = step_up_at, deny_at
        self.velocity = velocity or VelocityTracker()

    def evaluate(self, paise, subject, ctx=None):
        ctx = ctx or {}
        score, reasons, missing = 0, [], []
        if paise > 2000000:
            score += 30; reasons.append('amount above 20,000 INR')
        elif paise > 500000:
            score += 15; reasons.append('amount above 5,000 INR')
        if ctx.get('new_payee', True):
            score += 20; reasons.append('first payment to this payee')
        hour = ctx.get('hour')
        if hour is not None and (hour < 5 or hour >= 23):
            score += 10; reasons.append('unusual hour')
        count, total = self.velocity.window(subject, 3600)
        if count >= 3:
            score += 20; reasons.append('3 or more authorizations in the last hour')
        if total + paise > 5000000:
            score += 15; reasons.append('hourly total above 50,000 INR')
        if ctx.get('channel') == 'telephone':
            score += 5; reasons.append('narrowband telephone channel')
        if not ctx.get('device_bound'):
            score += 10; reasons.append('no device-bound key assertion')
        if ctx.get('challenge_verified') is False:
            score += 40; reasons.append('spoken one-time challenge failed')
        elif ctx.get('challenge_verified') is None:
            missing.append('challenge_verified')
        asv, cm = ctx.get('asv_score'), ctx.get('cm_score')
        if asv is None:
            missing.append('asv_score')
        elif asv < self.asv_min:
            score += 40; reasons.append('speaker score below threshold')
        if cm is None:
            missing.append('cm_score')
        elif cm < self.cm_min:
            score += 50; reasons.append('spoof/replay countermeasure score below threshold')
        score = min(score, 100)
        if score >= self.deny_at:
            action = 'deny'
        elif score >= self.step_up_at or missing:
            action = 'step_up'
            if missing:
                reasons.append('missing evidence: ' + ', '.join(missing))
        else:
            action = 'allow'
        return RiskDecision(score, action, reasons, missing)

    def record_outcome(self, subject, paise):
        self.velocity.record(subject, paise)
