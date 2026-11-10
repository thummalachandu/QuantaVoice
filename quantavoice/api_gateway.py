"""QuantaVoice REST API v1 (loopback research gateway): API keys, rate limits, idempotency,
signed webhooks, risk scoring, audit trail and an OpenAPI document.

SECURITY BOUNDARY: this gateway has no TLS and refuses to bind to anything but loopback. Evidence
fields (speaker/spoof scores, device claim) come from the authenticated partner and are not
independently verified here. Real approval still needs the backend operator console (demo).
"""
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import ssl
import threading
import time
import uuid
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, build_opener, ProxyHandler

from device_gateway import DeviceError
from privacy_consent import PURPOSES
from risk_engine import RiskEngine

API_VERSION = '1.0.0'
CONTEXT_FIELDS = {'new_payee': bool, 'hour': int, 'channel': str, 'device_bound': bool,
                  'asv_score': float, 'cm_score': float, 'challenge_verified': bool}
CHANNELS = {'app', 'web', 'telephone'}
# v17.1: evidence fields that are biometric processing, and the consent purpose each one needs.
BIOMETRIC_PURPOSE = {'asv_score': 'voice_verification', 'cm_score': 'anti_spoofing'}
CONSENT_SCOPES = ('consents:read', 'consents:write')
DEVICE_SCOPES = ('devices:write',)
DEFAULT_SCOPES = ('authorizations:write', 'authorizations:read') + CONSENT_SCOPES + DEVICE_SCOPES
REF_PATTERN = r'[A-Za-z0-9_.:@-]{1,64}'
NOTICE_PATTERN = r'[A-Za-z0-9_.-]{1,32}'


class ApiError(Exception):
    def __init__(self, status, code, message, headers=None):
        super().__init__(message)
        self.status, self.code, self.headers = status, code, headers or {}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


class ApiKeys:
    def __init__(self):
        self.keys = {}

    def create(self, name, scopes=DEFAULT_SCOPES):
        key_id, secret = secrets.token_hex(4), secrets.token_urlsafe(32)
        self.keys[key_id] = {'name': name, 'scopes': set(scopes), 'hash': hashlib.sha256(secret.encode()).digest(),
                             'revoked': False}
        return 'qvk_%s.%s' % (key_id, secret)

    def revoke(self, key_id):
        self.keys[key_id]['revoked'] = True

    def authenticate(self, header, scope):
        m = re.fullmatch(r'Bearer qvk_([0-9a-f]{8})\.([A-Za-z0-9_-]{20,64})', header or '')
        record = self.keys.get(m.group(1)) if m else None
        # Always hash so unknown ids and wrong secrets cost the same.
        given = hashlib.sha256((m.group(2) if m else '').encode()).digest()
        if not m or not record or record['revoked'] or not hmac.compare_digest(record['hash'], given):
            raise ApiError(401, 'invalid_api_key', 'Missing, invalid or revoked API key.')
        if scope not in record['scopes']:
            raise ApiError(403, 'insufficient_scope', 'This key lacks the %s scope.' % scope)
        return m.group(1)


class RateLimiter:
    def __init__(self, per_second=5.0, burst=10, clock=time.monotonic):
        self.rate, self.burst, self.clock = per_second, burst, clock
        self.state, self.lock = {}, threading.Lock()

    def check(self, subject):
        with self.lock:
            now = self.clock()
            tokens, last = self.state.get(subject, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self.state[subject] = (tokens, now)
                raise ApiError(429, 'rate_limited', 'Too many requests.',
                               {'Retry-After': str(max(1, int((1 - tokens) / self.rate) + 1))})
            self.state[subject] = (tokens - 1, now)


def sign_webhook(secret, timestamp, body):
    mac = hmac.new(secret.encode(), ('%d.%s' % (timestamp, body)).encode(), hashlib.sha256).hexdigest()
    return 't=%d,v1=%s' % (timestamp, mac)


def verify_webhook(secret, header, body, tolerance=300, now=None):
    m = re.fullmatch(r't=(\d{1,12}),v1=([0-9a-f]{64})', header or '')
    if not m:
        return False
    ts = int(m.group(1))
    if abs((now if now is not None else time.time()) - ts) > tolerance:
        return False
    return hmac.compare_digest(sign_webhook(secret, ts, body), header)


def validate_webhook_url(url, allow_local=False):
    u = urlparse(url)
    if u.scheme not in ('https', 'http') or not u.hostname or u.username or u.password:
        raise ValueError('Webhook URL must be absolute, without credentials.')
    if u.scheme == 'http' and not allow_local:
        raise ValueError('Webhook URL must use https.')
    try:
        addresses = {ipaddress.ip_address(u.hostname)}
    except ValueError:
        try:
            addresses = {ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(u.hostname, u.port or 443)}
        except OSError as exc:
            raise ValueError('Webhook host does not resolve.') from exc
    for a in addresses:
        if (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast) and not allow_local:
            raise ValueError('Webhook host resolves to a non-public address.')
    return url


def http_sink(url, headers, body):
    opener = build_opener(ProxyHandler({}))
    req = Request(url, data=body.encode(), headers=dict(headers, **{'Content-Type': 'application/json'}), method='POST')
    with opener.open(req, timeout=5) as r:
        if not 200 <= r.status < 300:
            raise IOError('Webhook endpoint returned %d' % r.status)


class WebhookDispatcher:
    def __init__(self, sink=http_sink, clock=time.time, allow_local=False):
        self.sink, self.clock, self.allow_local = sink, clock, allow_local
        self.endpoints, self.failed = [], []

    def register(self, url, secret):
        if len(secret) < 16:
            raise ValueError('Webhook secret must be at least 16 characters.')
        self.endpoints.append((validate_webhook_url(url, self.allow_local), secret))

    def _deliver(self, url, secret, body):
        ts = int(self.clock())
        self.sink(url, {'QuantaVoice-Signature': sign_webhook(secret, ts, body)}, body)

    def emit(self, event_type, data):
        body = canonical({'id': 'evt_' + secrets.token_hex(8), 'type': event_type,
                          'created': int(self.clock()), 'data': data})
        for url, secret in self.endpoints:
            try:
                self._deliver(url, secret, body)
            except Exception:
                self.failed.append((url, secret, body))
        return body

    def retry_failed(self):
        pending, self.failed = self.failed, []
        for url, secret, body in pending:
            try:
                self._deliver(url, secret, body)
            except Exception:
                self.failed.append((url, secret, body))
        return len(pending) - len(self.failed)


class AuthorizationService:
    def __init__(self, store, audit, risk=None, challenges=None, dispatcher=None, consent=None, vault=None, devices=None):
        # consent: a privacy_consent.ConsentLedger. None keeps v17 behaviour (consent not enforced).
        # vault: optional privacy_consent.TemplateVault, so erase also deletes the stored voiceprint.
        self.consent, self.vault = consent, vault
        self.devices = devices  # device_gateway.DeviceVerifier; None means no gateway-side device verification (v17.1)
        self._anon = secrets.token_bytes(32)
        self.store, self.audit = store, audit
        self.risk = risk or RiskEngine()
        self.challenges, self.dispatcher = challenges, dispatcher
        self.lock = threading.RLock()
        self.sessions, self.idem, self.auth = {}, {}, {}

    def _token(self, key_id):
        now = self.store.clock()
        saved = self.sessions.get(key_id)
        if not saved or now >= saved[1] - 60:
            s = self.store.session(self.store.bootstrap_token)  # one backend session (owner) per API key
            saved = self.sessions[key_id] = (s['token'], s['expires'])
        return saved[0]

    @staticmethod
    def _context(raw):
        if raw is None:
            return {}
        if not isinstance(raw, dict) or set(raw) - set(CONTEXT_FIELDS):
            raise ApiError(400, 'invalid_context', 'Unknown or malformed context fields.')
        out = {}
        for k, v in raw.items():
            kind = CONTEXT_FIELDS[k]
            if kind is float and isinstance(v, int) and not isinstance(v, bool):
                v = float(v)
            if not isinstance(v, kind) or (kind is int and isinstance(v, bool)):
                raise ApiError(400, 'invalid_context', 'Field %s has the wrong type.' % k)
            if kind is float and not 0.0 <= v <= 1.0:
                raise ApiError(400, 'invalid_context', 'Scores must be between 0 and 1.')
            if k == 'hour' and not 0 <= v <= 23:
                raise ApiError(400, 'invalid_context', 'hour must be 0 to 23.')
            if k == 'channel' and v not in CHANNELS:
                raise ApiError(400, 'invalid_context', 'channel must be app, web or telephone.')
            out[k] = v
        return out

    def create(self, key_id, body, idem_key):
        if not isinstance(idem_key, str) or not 8 <= len(idem_key) <= 64 or not re.fullmatch(r'[A-Za-z0-9_.:-]+', idem_key):
            raise ApiError(400, 'idempotency_key_required', 'Send an Idempotency-Key header (8-64 safe characters).')
        if not isinstance(body, dict) or not {'recipient', 'destination', 'amount'} <= set(body) \
                or set(body) - {'recipient', 'destination', 'amount', 'note', 'customer_ref', 'context'}:
            raise ApiError(400, 'invalid_request', 'Provide recipient, destination, amount and optionally note, customer_ref, context.')
        fingerprint = hashlib.sha256(canonical(body).encode()).hexdigest()
        with self.lock:
            prior = self.idem.get((key_id, idem_key))
            if prior:
                if prior[0] != fingerprint:
                    raise ApiError(422, 'idempotency_conflict', 'This Idempotency-Key was used with different parameters.')
                return prior[1], True
            try:
                amount = str(body['amount'])
                value = Decimal(amount)
                if not value.is_finite() or value <= 0 or value > 50000 or value != value.quantize(Decimal('0.01')):
                    raise ValueError
                paise = int(value * 100)
            except (InvalidOperation, ValueError, OverflowError):
                raise ApiError(400, 'invalid_amount', 'amount must be above 0 and at most 50000 with two decimals.')
            ctx = self._context(body.get('context'))
            needs = self._needs(ctx)
            raw_ref = self._check_consent(key_id, body.get('customer_ref'), needs, 'create')
            subject = '%s:%s' % (key_id, body.get('customer_ref', ''))
            decision = self.risk.evaluate(paise, subject, ctx)
            base = {'risk': decision.as_dict(), 'simulated': True}
            if decision.action == 'deny':
                self.audit.append('authorization.declined', {'key': key_id, 'risk_score': decision.score,
                                                             'reasons': decision.reasons})
                response = dict(base, id=None, status='declined')
                self.idem[(key_id, idem_key)] = (fingerprint, response)
                self._emit('authorization.declined', {'risk': decision.as_dict()})
                return response, False
            try:
                prepared = self.store.prepare(self._token(key_id), {
                    'recipient': str(body['recipient']), 'destination': str(body['destination']),
                    'rupees': amount, 'note': str(body.get('note', ''))})
            except (ValueError, TypeError) as exc:
                raise ApiError(400, 'invalid_request', str(exc))
            intent = prepared['intent']
            self.auth[intent['id']] = {'key_id': key_id, 'subject': subject, 'paise': intent['paise'],
                                       'recipient': intent['recipient'], 'destination': intent['destination'],
                                       'risk_action': decision.action, 'challenge_ok': decision.action == 'allow',
                                       'digest': prepared['digest'], 'needs': needs, 'consent_ref': raw_ref,
                                       'ref': body.get('customer_ref'), 'device_ok': False}
            response = dict(base, id=intent['id'], status='pending_review', digest=prepared['digest'],
                            expires_at=intent['expires'], step_up_required=decision.action == 'step_up',
                            amount_paise=intent['paise'], currency='INR',
                            recipient=intent['recipient'], destination=intent['destination'])
            self.idem[(key_id, idem_key)] = (fingerprint, response)
            self.audit.append('authorization.created', {'key': key_id, 'id': intent['id'],
                                                        'amount_paise': intent['paise'], 'risk_score': decision.score,
                                                        'risk_action': decision.action})
            self._emit('authorization.created', {'id': intent['id'], 'risk_action': decision.action})
            return response, False

    def _emit(self, event, data):
        if self.dispatcher:
            self.dispatcher.emit(event, data)

    def _own(self, key_id, auth_id):
        item = self.auth.get(auth_id)
        if not item or item['key_id'] != key_id:
            raise ApiError(404, 'not_found', 'No such authorization.')
        return item

    def get(self, key_id, auth_id):
        item = self._own(key_id, auth_id)
        row = self.store.db.execute('SELECT status, expires FROM transactions WHERE id=?', (auth_id,)).fetchone()
        status = row['status'] if row else 'unknown'
        if status in ('pending', 'approved') and self.store.clock() >= row['expires']:
            status = 'expired'
        return {'id': auth_id, 'status': status, 'digest': item['digest'], 'amount_paise': item['paise'],
                'recipient': item['recipient'], 'destination': item['destination'], 'currency': 'INR',
                'step_up_required': item['risk_action'] == 'step_up' and not item['challenge_ok'],
                'device_verified': bool(item.get('device_ok')), 'simulated': True}

    def issue_challenge(self, key_id, auth_id, lang='en'):
        item = self._own(key_id, auth_id)
        if self.challenges is None:
            raise ApiError(501, 'not_available', 'Challenge service not configured.')
        try:
            c = self.challenges.issue(item['digest'], lang)
        except ValueError as exc:
            raise ApiError(400, 'invalid_request', str(exc))
        self.audit.append('challenge.issued', {'id': auth_id, 'lang': lang})
        return c

    def verify_challenge(self, key_id, auth_id, challenge_id, transcript):
        item = self._own(key_id, auth_id)
        ok = bool(self.challenges and self.challenges.verify(challenge_id, item['digest'], str(transcript)))
        if ok:
            item['challenge_ok'] = True
        self.audit.append('challenge.verified' if ok else 'challenge.failed', {'id': auth_id})
        return {'verified': ok}

    def confirm(self, key_id, auth_id, digest):
        item = self._own(key_id, auth_id)
        if item.get('needs') and item.get('consent_ref'):  # withdrawal before consumption must stop the payment
            self._check_consent(key_id, item['consent_ref'].split(':', 1)[1], item['needs'], 'confirm')
        if not item['challenge_ok']:
            self.audit.append('authorization.confirm_failed', {'id': auth_id, 'reason': 'step_up_required'})
            raise ApiError(403, 'step_up_required', 'Verify the spoken challenge before confirming.')
        try:
            result = self.store.confirm(self._token(key_id), {'id': auth_id, 'digest': str(digest)})
        except (ValueError, PermissionError) as exc:
            self.audit.append('authorization.confirm_failed', {'id': auth_id, 'reason': str(exc)[:80]})
            raise ApiError(409, 'confirm_failed', str(exc))
        self.risk.record_outcome(item['subject'], item['paise'])
        self.audit.append('authorization.confirmed', {'id': auth_id, 'amount_paise': item['paise']})
        self._emit('authorization.confirmed', {'id': auth_id})
        return {'id': auth_id, 'status': 'consumed', 'receipt_id': result['receipt_id'], 'simulated': True}

    # ---- v17.1: biometric privacy consent -------------------------------------------------------
    @staticmethod
    def _needs(ctx):
        return sorted({BIOMETRIC_PURPOSE[k] for k in ctx if k in BIOMETRIC_PURPOSE})

    def _pseudonym(self, raw):
        if self.consent is None:
            return hmac.new(self._anon, raw.encode(), hashlib.sha256).hexdigest()[:16]
        return self.consent.subject(raw)[:16]  # audit log never holds the customer reference

    def _raw(self, key_id, ref):
        if not isinstance(ref, str) or not re.fullmatch(REF_PATTERN, ref):
            raise ApiError(400, 'invalid_customer_ref', 'customer_ref must be 1-64 characters: letters, digits, _ . : @ -')
        return '%s:%s' % (key_id, ref)  # consent is scoped to the API key that collected it

    def _check_consent(self, key_id, ref, needs, stage):
        """Fail closed: biometric evidence without valid consent never reaches the risk engine or the ledger."""
        if self.consent is None or not needs:
            return None
        if not ref:
            raise ApiError(400, 'customer_ref_required', 'Biometric evidence needs a customer_ref so consent can be checked.')
        raw = self._raw(key_id, ref)
        missing = [p for p in needs if not self.consent.allowed(raw, p)]
        if missing:
            self.audit.append('consent.denied', {'key': key_id, 'subject': self._pseudonym(raw), 'purposes': missing,
                                                 'stage': stage})
            if stage == 'confirm':
                raise ApiError(403, 'consent_withdrawn', 'Consent was withdrawn or expired for: %s. Nothing was authorized.'
                               % ', '.join(missing))
            raise ApiError(403, 'consent_required', 'No valid consent for: %s.' % ', '.join(missing))
        return raw

    def _need_consent(self):
        if self.consent is None:
            raise ApiError(501, 'not_available', 'Privacy consent is not configured on this gateway.')

    @staticmethod
    def _object(body, allowed, required):
        if not isinstance(body, dict) or set(body) - set(allowed) or not set(required) <= set(body):
            raise ApiError(400, 'invalid_request', 'Provide %s%s.' % (', '.join(required),
                           (' and optionally ' + ', '.join(sorted(set(allowed) - set(required)))) if set(allowed) - set(required) else ''))
        return body

    def _view(self, raw, ref):
        return {'enforced': True, 'customer_ref': ref,
                'purposes': {p: self.consent.allowed(raw, p) for p in PURPOSES}}

    def consent_status(self, key_id, ref):
        if self.consent is None:
            return {'enforced': False, 'purposes': {}}
        out = self._view(self._raw(key_id, ref), ref)
        out['history'] = self.consent.history(self._raw(key_id, ref))  # consent events only, never biometric content
        return out

    def consent_grant(self, key_id, body):
        self._need_consent()
        body = self._object(body, ('customer_ref', 'purposes', 'notice_version', 'ttl_days'),
                            ('customer_ref', 'purposes', 'notice_version'))
        raw = self._raw(key_id, body['customer_ref'])
        purposes = body['purposes']
        if not isinstance(purposes, list) or not purposes or len(set(purposes)) != len(purposes) \
                or any(p not in PURPOSES for p in purposes):
            raise ApiError(400, 'invalid_purpose', 'purposes must be a non-empty list from: %s.' % ', '.join(PURPOSES))
        notice = body['notice_version']
        if not isinstance(notice, str) or not re.fullmatch(NOTICE_PATTERN, notice):
            raise ApiError(400, 'invalid_notice_version', 'notice_version must be 1-32 characters: letters, digits, _ . -')
        ttl = body.get('ttl_days', 365)
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not 0 < ttl <= 3650:
            raise ApiError(400, 'invalid_ttl', 'ttl_days must be above 0 and at most 3650.')
        for p in purposes:
            self.consent.grant(raw, p, notice, ttl)
        self.audit.append('consent.granted', {'key': key_id, 'subject': self._pseudonym(raw), 'purposes': sorted(purposes),
                                              'notice_version': notice, 'ttl_days': ttl})
        return self._view(raw, body['customer_ref'])

    def consent_withdraw(self, key_id, body):
        self._need_consent()
        body = self._object(body, ('customer_ref', 'purpose'), ('customer_ref',))
        raw, purpose = self._raw(key_id, body['customer_ref']), body.get('purpose')
        if purpose is not None and purpose not in PURPOSES:
            raise ApiError(400, 'invalid_purpose', 'Unknown purpose.')
        n = self.consent.withdraw(raw, purpose)
        self.audit.append('consent.withdrawn', {'key': key_id, 'subject': self._pseudonym(raw),
                                                'purpose': purpose or 'all', 'records': n})
        return dict(self._view(raw, body['customer_ref']), withdrawn=n)

    def consent_erase(self, key_id, body):
        """Withdraw everything and crypto-erase the stored voiceprint (if a vault is configured)."""
        self._need_consent()
        body = self._object(body, ('customer_ref',), ('customer_ref',))
        raw = self._raw(key_id, body['customer_ref'])
        n = self.consent.withdraw(raw)
        erased = bool(self.vault.erase(raw, 'subject_request')) if self.vault is not None else False
        self.audit.append('consent.erased', {'key': key_id, 'subject': self._pseudonym(raw), 'withdrawn': n,
                                             'template_erased': erased})
        return dict(self._view(raw, body['customer_ref']), withdrawn=n, template_erased=erased)

    # ---- v17.2: gateway-verified customer device (WebAuthn), bound to the transaction digest ------
    def _need_devices(self):
        if self.devices is None:
            raise ApiError(501, 'not_available', 'Device verification is not configured on this gateway.')

    @staticmethod
    def _device_call(fn, *args):
        try:
            return fn(*args)
        except DeviceError as exc:
            raise ApiError(exc.status, exc.code, str(exc)) from None

    def device_register_begin(self, key_id, body):
        self._need_devices()
        body = self._object(body, ('customer_ref',), ('customer_ref',))
        ref = self._raw(key_id, body['customer_ref']).split(':', 1)[1]
        return self._device_call(self.devices.register_begin, key_id, ref)

    def device_register_complete(self, key_id, body):
        self._need_devices()
        body = self._object(body, ('customer_ref', 'session', 'response'), ('customer_ref', 'session', 'response'))
        raw = self._raw(key_id, body['customer_ref']); ref = body['customer_ref']
        if not isinstance(body['response'], dict):
            raise ApiError(400, 'invalid_request', 'response must be the WebAuthn registration object.')
        try:
            out = self._device_call(self.devices.register_complete, key_id, ref, body['session'], body['response'])
        except ApiError as exc:
            self.audit.append('device.registration_failed', {'key': key_id, 'subject': self._pseudonym(raw), 'code': exc.code})
            raise
        self.audit.append('device.registered', {'key': key_id, 'subject': self._pseudonym(raw), 'attestation': out['attestation']})
        return out

    def _device_context(self, key_id, auth_id):
        item = self._own(key_id, auth_id)
        if not item.get('ref'):
            raise ApiError(400, 'customer_ref_required', 'Create the authorization with a customer_ref to use a device.')
        ref = self._raw(key_id, item['ref']).split(':', 1)[1]
        return item, ref

    def device_begin(self, key_id, auth_id):
        self._need_devices()
        item, ref = self._device_context(key_id, auth_id)
        if self.get(key_id, auth_id)['status'] in ('consumed', 'expired', 'rejected', 'denied'):
            raise ApiError(409, 'not_open', 'This authorization is not open.')
        out = self._device_call(self.devices.assertion_begin, key_id, ref, auth_id, item['digest'])
        self.audit.append('device.challenge_issued', {'id': auth_id})
        return out

    def device_complete(self, key_id, auth_id, body):
        self._need_devices()
        item, ref = self._device_context(key_id, auth_id)
        body = self._object(body, ('session', 'response'), ('session', 'response'))
        if not isinstance(body['response'], dict):
            raise ApiError(400, 'invalid_request', 'response must be the WebAuthn assertion object.')
        try:
            out = self._device_call(self.devices.assertion_complete, key_id, ref, auth_id, body['session'], body['response'])
        except ApiError as exc:
            self.audit.append('device.assertion_failed', {'id': auth_id, 'code': exc.code})
            raise
        item['device_ok'] = True
        item['challenge_ok'] = True  # a verified device signature over this digest satisfies step-up
        self.audit.append('device.assertion_verified', {'id': auth_id, 'attestation': out['attestation']})
        return out


def openapi_spec():
    err = {'$ref': '#/components/schemas/Error'}
    def resp(desc, schema=None):
        r = {'description': desc}
        if schema:
            r['content'] = {'application/json': {'schema': schema}}
        return r
    sec = [{'bearerAuth': []}]
    idem = {'name': 'Idempotency-Key', 'in': 'header', 'required': True, 'schema': {'type': 'string', 'minLength': 8, 'maxLength': 64}}
    pid = {'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}
    return {'openapi': '3.0.3',
            'info': {'title': 'QuantaVoice Authorization API', 'version': API_VERSION,
                     'description': 'Loopback research API. Simulated funds only. No TLS; not for production.'},
            'servers': [{'url': 'http://127.0.0.1:{port}', 'variables': {'port': {'default': '8080'}}}],
            'paths': {
                '/v1/health': {'get': {'summary': 'Liveness', 'responses': {'200': resp('OK')}}},
                '/v1/openapi.json': {'get': {'summary': 'This document', 'responses': {'200': resp('OpenAPI document')}}},
                '/v1/authorizations': {'post': {'summary': 'Create a payment authorization request', 'security': sec,
                    'parameters': [idem],
                    'requestBody': {'required': True, 'content': {'application/json': {'schema': {'$ref': '#/components/schemas/CreateAuthorization'}}}},
                    'responses': {'201': resp('Created'), '200': resp('Idempotent replay'), '400': resp('Invalid', err),
                                  '401': resp('Unauthorized', err), '403': resp('consent_required: biometric evidence without valid consent', err), '422': resp('Idempotency conflict', err), '429': resp('Rate limited', err)}}},
                '/v1/authorizations/{id}': {'get': {'summary': 'Read status', 'security': sec, 'parameters': [pid],
                    'responses': {'200': resp('OK'), '404': resp('Not found', err)}}},
                '/v1/authorizations/{id}/challenge': {'post': {'summary': 'Issue a one-time spoken challenge', 'security': sec,
                    'parameters': [pid], 'responses': {'200': resp('Challenge')}}},
                '/v1/authorizations/{id}/challenge/verify': {'post': {'summary': 'Verify the transcript of the spoken challenge',
                    'security': sec, 'parameters': [pid], 'responses': {'200': resp('Result')}}},
                '/v1/authorizations/{id}/confirm': {'post': {'summary': 'Consume an approved authorization', 'security': sec,
                    'parameters': [pid], 'responses': {'200': resp('Consumed'), '403': resp('Step-up required, or consent withdrawn', err), '409': resp('Not approved', err)}}},
                '/v1/devices/register/begin': {'post': {'summary': 'Start WebAuthn registration of a customer device', 'security': sec,
                    'responses': {'200': resp('Creation options and session'), '501': resp('Not configured', err)}}},
                '/v1/devices/register/complete': {'post': {'summary': 'Finish registration; returns attestation level', 'security': sec,
                    'responses': {'200': resp('Registered'), '400': resp('Rejected', err)}}},
                '/v1/authorizations/{id}/device/begin': {'post': {'summary': 'WebAuthn challenge that commits to this transaction digest',
                    'security': sec, 'parameters': [pid], 'responses': {'200': resp('Request options, session, digest, nonce')}}},
                '/v1/authorizations/{id}/device/complete': {'post': {'summary': 'Verify the device assertion; satisfies step-up',
                    'security': sec, 'parameters': [pid], 'responses': {'200': resp('Verified'), '400': resp('Rejected', err)}}},
                '/v1/consents': {'post': {'summary': 'Record biometric consent for a customer (partner-attested)', 'security': sec,
                    'requestBody': {'required': True, 'content': {'application/json': {'schema': {'$ref': '#/components/schemas/GrantConsent'}}}},
                    'responses': {'200': resp('Consent status'), '400': resp('Invalid', err), '403': resp('Missing scope', err),
                                  '501': resp('Consent not configured', err)}}},
                '/v1/consents/withdraw': {'post': {'summary': 'Withdraw consent (one purpose or all)', 'security': sec,
                    'responses': {'200': resp('Consent status')}}},
                '/v1/consents/erase': {'post': {'summary': 'Withdraw all consent and erase the stored voiceprint', 'security': sec,
                    'responses': {'200': resp('Erasure result')}}},
                '/v1/consents/{ref}': {'get': {'summary': 'Consent status and consent history (no biometric content)', 'security': sec,
                    'parameters': [{'name': 'ref', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}],
                    'responses': {'200': resp('Status')}}}},
            'components': {
                'securitySchemes': {'bearerAuth': {'type': 'http', 'scheme': 'bearer'}},
                'schemas': {
                    'GrantConsent': {'type': 'object', 'required': ['customer_ref', 'purposes', 'notice_version'], 'properties': {
                        'customer_ref': {'type': 'string'}, 'purposes': {'type': 'array', 'items': {'type': 'string', 'enum': list(PURPOSES)}},
                        'notice_version': {'type': 'string'}, 'ttl_days': {'type': 'number', 'default': 365}}},
                    'Error': {'type': 'object', 'properties': {'error': {'type': 'object', 'properties': {
                        'code': {'type': 'string'}, 'message': {'type': 'string'}}}}},
                    'CreateAuthorization': {'type': 'object', 'required': ['recipient', 'destination', 'amount'], 'properties': {
                        'recipient': {'type': 'string', 'maxLength': 60}, 'destination': {'type': 'string', 'example': 'chandu@demo'},
                        'amount': {'type': 'string', 'example': '5000.00'}, 'note': {'type': 'string', 'maxLength': 140},
                        'customer_ref': {'type': 'string'},
                        'context': {'type': 'object', 'properties': {
                            'new_payee': {'type': 'boolean'}, 'hour': {'type': 'integer'},
                            'channel': {'type': 'string', 'enum': sorted(CHANNELS)}, 'device_bound': {'type': 'boolean'},
                            'asv_score': {'type': 'number'}, 'cm_score': {'type': 'number'}, 'challenge_verified': {'type': 'boolean'}}}}}}},
            'x-webhooks': {'events': ['authorization.created', 'authorization.declined', 'authorization.confirmed'],
                           'signature': 'QuantaVoice-Signature: t=<unix>,v1=HMAC-SHA256(secret, "<t>.<body>")'}}


def make_handler(service, keys, limiter):
    routes = [('POST', r'/v1/authorizations', 'create'), ('GET', r'/v1/authorizations/([0-9a-f]{32})', 'get'),
              ('POST', r'/v1/authorizations/([0-9a-f]{32})/challenge', 'challenge'),
              ('POST', r'/v1/authorizations/([0-9a-f]{32})/challenge/verify', 'verify'),
              ('POST', r'/v1/authorizations/([0-9a-f]{32})/confirm', 'confirm'),
              ('POST', r'/v1/authorizations/([0-9a-f]{32})/device/begin', 'device_begin'),
              ('POST', r'/v1/authorizations/([0-9a-f]{32})/device/complete', 'device_complete'),
              ('POST', r'/v1/devices/register/begin', 'device_register_begin'),
              ('POST', r'/v1/devices/register/complete', 'device_register_complete'),
              ('POST', r'/v1/consents', 'consent_grant'), ('POST', r'/v1/consents/withdraw', 'consent_withdraw'),
              ('POST', r'/v1/consents/erase', 'consent_erase'), ('GET', r'/v1/consents/(%s)' % REF_PATTERN, 'consent_status')]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, status, payload, extra=None):
            raw = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            for k, v in dict({'Content-Type': 'application/json; charset=utf-8', 'Content-Length': str(len(raw)),
                              'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                              'X-Request-Id': uuid.uuid4().hex}, **(extra or {})).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def handle_any(self, method):
            self.connection.settimeout(5)
            try:
                if self.headers.get('Origin') is not None:
                    raise ApiError(403, 'origin_not_allowed', 'Browser-origin requests are disabled.')
                if self.path == '/v1/health' and method == 'GET':
                    return self.reply(200, {'status': 'ok', 'version': API_VERSION, 'simulated': True})
                if self.path == '/v1/openapi.json' and method == 'GET':
                    return self.reply(200, openapi_spec())
                for m, pattern, name in routes:
                    hit = re.fullmatch(pattern, self.path)
                    if m == method and hit:
                        break
                else:
                    raise ApiError(404, 'not_found', 'No such endpoint.')
                if name.startswith('device_register'):
                    scope = 'devices:write'
                elif name.startswith('consent'):
                    scope = 'consents:read' if method == 'GET' else 'consents:write'
                else:
                    scope = 'authorizations:read' if method == 'GET' else 'authorizations:write'
                try:
                    key_id = keys.authenticate(self.headers.get('Authorization'), scope)
                except ApiError as exc:
                    service.audit.append('auth.failed', {'path': self.path, 'code': exc.code})
                    raise
                try:
                    limiter.check(key_id)
                except ApiError:
                    service.audit.append('rate_limited', {'key': key_id})
                    raise
                body = {}
                if method == 'POST':
                    if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                        raise ApiError(415, 'unsupported_media_type', 'Use application/json.')
                    length = int(self.headers.get('Content-Length', '-1'))
                    if not 0 <= length <= 16384:
                        raise ApiError(413, 'too_large', 'Body must be at most 16 KB.')
                    try:
                        body = json.loads(self.rfile.read(length) or b'{}')
                    except ValueError:
                        raise ApiError(400, 'invalid_json', 'Body is not valid JSON.')
                if name == 'create':
                    out, replay = service.create(key_id, body, self.headers.get('Idempotency-Key'))
                    return self.reply(200 if replay else 201, out, {'Idempotent-Replayed': 'true'} if replay else None)
                if name.startswith('device_register'):
                    return self.reply(200, getattr(service, name)(key_id, body))
                if name == 'consent_status':
                    return self.reply(200, service.consent_status(key_id, hit.group(1)))
                if name.startswith('consent_'):
                    return self.reply(200, getattr(service, name)(key_id, body))
                auth_id = hit.group(1)
                if name == 'device_begin':
                    out = service.device_begin(key_id, auth_id)
                elif name == 'device_complete':
                    out = service.device_complete(key_id, auth_id, body)
                elif name == 'get':
                    out = service.get(key_id, auth_id)
                elif name == 'challenge':
                    out = service.issue_challenge(key_id, auth_id, body.get('lang', 'en') if isinstance(body, dict) else 'en')
                elif name == 'verify':
                    if not isinstance(body, dict):
                        raise ApiError(400, 'invalid_request', 'Object body required.')
                    out = service.verify_challenge(key_id, auth_id, str(body.get('challenge_id', '')), body.get('transcript', ''))
                else:
                    if not isinstance(body, dict):
                        raise ApiError(400, 'invalid_request', 'Object body required.')
                    out = service.confirm(key_id, auth_id, body.get('digest', ''))
                self.reply(200, out)
            except ApiError as exc:
                self.reply(exc.status, {'error': {'code': exc.code, 'message': str(exc)}}, exc.headers)
            except Exception:
                self.reply(500, {'error': {'code': 'internal_error', 'message': 'Request failed. No payment authorized.'}})

        def do_GET(self):
            self.handle_any('GET')

        def do_POST(self):
            self.handle_any('POST')
    return Handler


class TlsConfig:
    """Transport security for the gateway. client_ca turns on mutual TLS: clients must present a certificate it signed."""

    def __init__(self, certfile, keyfile, client_ca=None, tls13_only=False):
        self.certfile, self.keyfile, self.client_ca, self.tls13_only = certfile, keyfile, client_ca, tls13_only

    def context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3 if self.tls13_only else ssl.TLSVersion.TLSv1_2  # never 1.0 / 1.1
        ctx.load_cert_chain(self.certfile, self.keyfile)
        if self.client_ca:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(self.client_ca)
        return ctx


class _TLSServer(ThreadingHTTPServer):
    """The handshake runs in the connection's own thread, so a client that stalls cannot block other clients."""
    ssl_context = None
    handshake_timeout = 10

    def finish_request(self, request, client_address):
        request.settimeout(self.handshake_timeout)
        try:
            tls = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return  # bad or missing client certificate, wrong protocol, plain HTTP, port scan: drop quietly
        try:
            tls.settimeout(30)
            super().finish_request(tls, client_address)
        finally:
            # Orderly close: send close_notify, then briefly drain what the client still sends. Closing with unread
            # request bytes (an early 401 before the body was read) would reset the connection and lose the reply.
            try:
                tls.settimeout(1)
                raw = tls.unwrap()
                raw.shutdown(socket.SHUT_WR)
                for _ in range(64):
                    if not raw.recv(4096):
                        break
            except (OSError, ValueError):
                pass
            try:
                tls.close()
            except OSError:
                pass


def serve(service, keys, limiter=None, host='127.0.0.1', port=0, tls=None):
    if tls is None and host not in ('127.0.0.1', 'localhost', '::1'):
        raise ValueError('Without TLS this gateway binds to loopback only. Pass tls=TlsConfig(...) to listen elsewhere.')
    if tls is None:
        server = ThreadingHTTPServer((host, port), make_handler(service, keys, limiter or RateLimiter()))
    else:
        server = _TLSServer((host, port), make_handler(service, keys, limiter or RateLimiter()))
        server.ssl_context = tls.context()
    server.tls_enabled = tls is not None
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
