"""Desktop client for the v16 REST gateway. Fails closed: an outage never becomes a local payment."""
import json
import os
import re
import secrets
import time
from decimal import Decimal
from pathlib import Path

import sdk
from consent_notice import DESKTOP_PURPOSES, NOTICE_VERSION
from evidence import DATA


class GatewayUnavailable(Exception):
    """Network or server problem. No payment was made."""


class GatewayRejected(Exception):
    def __init__(self, code, message):
        super().__init__('%s: %s' % (code, message))
        self.code = code


class IntentMismatch(Exception):
    """The API bound something different from what the person reviewed."""


DEST = re.compile(r'[A-Za-z0-9_.-]{1,64}@demo')


class GatewayBridge:
    def __init__(self, base_url, api_key, customer_ref='desktop-gui', timeout=4, cafile=None, client_cert=None, client_key=None):
        self.client = sdk.Client(base_url, api_key, retries=1, sleep=lambda s: time.sleep(min(s, 0.5)), timeout=timeout,
                                 cafile=cafile, client_cert=client_cert, client_key=client_key)
        self.customer_ref = customer_ref

    @classmethod
    def from_environment(cls, path=None):
        """None when nothing is configured (v16 behaviour). Raises ValueError for a broken configuration."""
        url, key = os.environ.get('QUANTAVOICE_API_URL'), os.environ.get('QUANTAVOICE_API_KEY')
        tls = {'cafile': os.environ.get('QUANTAVOICE_API_CA'), 'client_cert': os.environ.get('QUANTAVOICE_API_CLIENT_CERT'),
               'client_key': os.environ.get('QUANTAVOICE_API_CLIENT_KEY')}
        path = Path(path) if path else DATA / 'gateway_config.json'
        if not (url and key) and path.is_file():
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
                url, key = data['base_url'], data['api_key']
                tls = {'cafile': data.get('ca_file'), 'client_cert': data.get('client_cert'), 'client_key': data.get('client_key')}
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise ValueError('gateway_config.json must contain base_url and api_key.') from exc
        if not (url and key):
            return None
        if not re.fullmatch(r'qvk_[0-9a-f]{8}\.[A-Za-z0-9_-]{20,64}', key):
            raise ValueError('API key has the wrong format.')
        tls = {k: v for k, v in tls.items() if v}
        try:
            return cls(url, key, **tls)
        except (ValueError, OSError, __import__('ssl').SSLError) as exc:
            raise ValueError('TLS configuration is unusable: %s' % exc) from exc

    @staticmethod
    def broken(reason):
        return _BrokenGateway(reason)

    def _call(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except sdk.QuantaVoiceError as exc:
            raise GatewayRejected(exc.code, str(exc)) from None
        except (OSError, ValueError) as exc:  # URLError, timeouts, bad JSON
            raise GatewayUnavailable('Gateway unreachable (%s). No payment was made.' % type(exc).__name__) from None

    def create(self, recipient, destination, amount, note, context, idempotency_key):
        if not DEST.fullmatch(destination or ''):
            raise ValueError('The lab API accepts demo destinations (name@demo) only.')
        return self._call(self.client.create_authorization, recipient, destination, amount, note=note,
                          customer_ref=self.customer_ref, context=context, idempotency_key=idempotency_key)

    def status(self, auth_id):
        return self._call(self.client.get_authorization, auth_id)

    def challenge(self, auth_id, lang='en'):
        return self._call(self.client.issue_challenge, auth_id, lang)

    def verify_challenge(self, auth_id, challenge_id, transcript):
        return self._call(self.client.verify_challenge, auth_id, challenge_id, transcript)

    def confirm(self, auth_id, digest):
        return self._call(self.client.confirm_authorization, auth_id, digest)

    # v17.2: gateway-verified device
    def device_register_begin(self):
        return self._call(self.client.device_register_begin, self.customer_ref)

    def device_register_complete(self, session, response):
        return self._call(self.client.device_register_complete, self.customer_ref, session, response)

    def device_assertion_begin(self, auth_id):
        return self._call(self.client.device_assertion_begin, auth_id)

    def device_assertion_complete(self, auth_id, session, response):
        return self._call(self.client.device_assertion_complete, auth_id, session, response)

    # v17.1: privacy consent
    def consent_status(self):
        return self._call(self.client.consent_status, self.customer_ref)

    def grant_consent(self, purposes=DESKTOP_PURPOSES):
        return self._call(self.client.grant_consent, self.customer_ref, list(purposes), NOTICE_VERSION)

    def withdraw_consent(self, purpose=None):
        return self._call(self.client.withdraw_consent, self.customer_ref, purpose)

    def erase_data(self):
        return self._call(self.client.erase_customer_data, self.customer_ref)


class _BrokenGateway:
    """Installed when a gateway was configured but the configuration is unusable: block, never fall back."""

    def __init__(self, reason):
        self.reason = reason

    def _fail(self, *a, **k):
        raise GatewayUnavailable('Gateway configuration is unusable (%s). No payment was made.' % self.reason)
    create = status = challenge = verify_challenge = confirm = _fail
    consent_status = grant_consent = withdraw_consent = erase_data = _fail
    device_register_begin = device_register_complete = device_assertion_begin = device_assertion_complete = _fail


def check_echo(response, recipient, destination, amount):
    """The API must have bound exactly what the person reviewed."""
    paise = int((Decimal(str(amount)) * 100).to_integral_value())
    problems = []
    if response.get('amount_paise') != paise:
        problems.append('amount')
    if response.get('recipient') != recipient.strip():
        problems.append('recipient')
    if response.get('destination') != destination.strip():
        problems.append('destination')
    if response.get('currency') != 'INR':
        problems.append('currency')
    if problems:
        raise IntentMismatch('The API bound a different %s than the one you reviewed.' % ', '.join(problems))


def new_idempotency_key():
    return 'gui-' + secrets.token_hex(12)
