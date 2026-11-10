"""Small Python client for the QuantaVoice Authorization API (stdlib only)."""
import json
import re
import ssl
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, Request, build_opener, ProxyHandler


class QuantaVoiceError(Exception):
    def __init__(self, status, code, message):
        super().__init__('%s (%s): %s' % (status, code, message))
        self.status, self.code = status, code


class Client:
    def __init__(self, base_url, api_key, retries=3, sleep=time.sleep, timeout=10, cafile=None, client_cert=None, client_key=None):
        if not base_url.startswith(('http://127.0.0.1', 'http://localhost', 'https://')):
            raise ValueError('Use https:// (or loopback http for the local lab).')
        self.base, self.key, self.retries, self.sleep, self.timeout = base_url.rstrip('/'), api_key, retries, sleep, timeout
        handlers = [ProxyHandler({})]
        if base_url.startswith('https://'):
            # Verifies the server certificate and host name. cafile pins your own CA; client_cert/client_key give mutual TLS.
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if client_cert:
                ctx.load_cert_chain(client_cert, client_key)
            handlers.append(HTTPSHandler(context=ctx))
        elif cafile or client_cert:
            raise ValueError('cafile and client_cert only apply to https:// URLs.')
        self.opener = build_opener(*handlers)

    def _request(self, method, path, body=None, idem=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {'Authorization': 'Bearer ' + self.key, 'Content-Type': 'application/json'}
        if idem:
            headers['Idempotency-Key'] = idem
        for attempt in range(self.retries + 1):
            try:
                with self.opener.open(Request(self.base + path, data=data, headers=headers, method=method),
                                      timeout=self.timeout) as r:
                    return json.loads(r.read())
            except HTTPError as e:
                payload = json.loads(e.read() or b'{}').get('error', {})
                if e.code in (429, 503) and attempt < self.retries:
                    self.sleep(min(int(e.headers.get('Retry-After', 1)), 30))
                    continue
                raise QuantaVoiceError(e.code, payload.get('code', 'error'), payload.get('message', '')) from None
            except URLError:
                if attempt >= self.retries:
                    raise
                self.sleep(2 ** attempt)

    def create_authorization(self, recipient, destination, amount, note='', customer_ref=None, context=None,
                             idempotency_key=None):
        body = {'recipient': recipient, 'destination': destination, 'amount': str(amount), 'note': note}
        if customer_ref:
            body['customer_ref'] = customer_ref
        if context:
            body['context'] = context
        # One key reused across every retry makes the create call safe to repeat.
        return self._request('POST', '/v1/authorizations', body, idempotency_key or uuid.uuid4().hex)

    def get_authorization(self, auth_id):
        return self._request('GET', '/v1/authorizations/' + auth_id)

    def issue_challenge(self, auth_id, lang='en'):
        return self._request('POST', '/v1/authorizations/%s/challenge' % auth_id, {'lang': lang})

    def verify_challenge(self, auth_id, challenge_id, transcript):
        return self._request('POST', '/v1/authorizations/%s/challenge/verify' % auth_id,
                             {'challenge_id': challenge_id, 'transcript': transcript})

    def confirm_authorization(self, auth_id, digest):
        return self._request('POST', '/v1/authorizations/%s/confirm' % auth_id, {'digest': digest})

    # ---- v17.1: biometric privacy consent (the partner attests that the customer agreed) ----
    @staticmethod
    def _ref(customer_ref):
        if not isinstance(customer_ref, str) or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,64}', customer_ref):
            raise ValueError('customer_ref must be 1-64 characters: letters, digits, _ . : @ -')
        return customer_ref

    def grant_consent(self, customer_ref, purposes, notice_version, ttl_days=None):
        body = {'customer_ref': self._ref(customer_ref), 'purposes': list(purposes), 'notice_version': notice_version}
        if ttl_days is not None:
            body['ttl_days'] = ttl_days
        return self._request('POST', '/v1/consents', body)

    def withdraw_consent(self, customer_ref, purpose=None):
        body = {'customer_ref': self._ref(customer_ref)}
        if purpose:
            body['purpose'] = purpose
        return self._request('POST', '/v1/consents/withdraw', body)

    def consent_status(self, customer_ref):
        return self._request('GET', '/v1/consents/' + self._ref(customer_ref))

    def erase_customer_data(self, customer_ref):
        return self._request('POST', '/v1/consents/erase', {'customer_ref': self._ref(customer_ref)})

    # ---- v17.2: gateway-verified customer device (WebAuthn) ----
    def device_register_begin(self, customer_ref):
        return self._request('POST', '/v1/devices/register/begin', {'customer_ref': self._ref(customer_ref)})

    def device_register_complete(self, customer_ref, session, response):
        return self._request('POST', '/v1/devices/register/complete',
                             {'customer_ref': self._ref(customer_ref), 'session': session, 'response': response})

    def device_assertion_begin(self, auth_id):
        return self._request('POST', '/v1/authorizations/%s/device/begin' % auth_id, {})

    def device_assertion_complete(self, auth_id, session, response):
        return self._request('POST', '/v1/authorizations/%s/device/complete' % auth_id,
                             {'session': session, 'response': response})
