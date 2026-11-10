"""Seven-stage PRESENTATION workflow; simulated identity checks are explicit."""
import hashlib
import hmac
import secrets
import time
from core import Lab, tampered

NAMES = ['Voice + anti-spoofing', 'PIN / passphrase', 'OTP verification',
         'Face + liveness', 'Fingerprint / FIDO2', 'Agent / AI-assisted review',
         'Video KYC / branch review']

class Flow:
    def __init__(self, gateway=None):
        self.gateway = gateway  # None keeps the v16 local payment path exactly as it was
        self.consent = None     # last consent status from the gateway (v17.1); never guessed locally
        self.lab = Lab()
        self.salt = secrets.token_bytes(16)
        self.pin_hash = self.hash_pin('246810')
        self.reset()

    def hash_pin(self, pin):
        return hashlib.scrypt(pin.encode(), salt=self.salt, n=16384, r=8, p=1)

    def reset(self):
        self.revision=getattr(self,"revision",0)+1
        self.stage = -1
        self.states = ['WAITING'] * 7
        self.blocked = False
        self.tries = 0
        self.otp = None
        self.otp_tries = 0
        self.otp_deadline = 0
        self.packet = None
        self.intent = None
        self.contact_id = None
        self.note = ""
        self.voice_evidence = None   # only ever filled from real ASV+CM inference
        self.device_verified = False  # only ever set after an app-verified WebAuthn assertion
        self.channel = 'app'
        self.api = None
        self.api_idem = None
        self.receipt = None
        self.lab.pending.clear()

    def start(self, recipient, amount, contact_id=None, note=""):
        self.reset()
        _, intent, _ = self.lab.prepare(recipient, amount, contact_id, note)
        self.lab.pending.clear()
        self.recipient, self.amount = intent['recipient'], str(intent['paise'] / 100)
        self.contact_id, self.note = contact_id, note.strip()
        self.stage = 0

    def require(self, stage):
        if self.blocked or self.stage != stage:
            raise ValueError('This step is locked. Complete the current step or start a new demo.')

    def advance(self, label):
        self.states[self.stage] = label
        self.stage += 1

    def reject(self, reason):
        if self.stage < len(self.states): self.states[self.stage] = 'REJECTED'
        self.blocked = True
        self.lab.pending.clear()
        self.packet = None
        raise ValueError(reason + ' Payment blocked. Start a new demo to retry.')

    def scenario(self, stage, passed):
        self.require(stage)
        if stage not in (0, 3, 4, 5, 6):
            raise ValueError('This layer requires its own verification.')
        if not passed:
            self.reject('Simulated rejection at layer ' + str(stage+1) + '.')
        self.advance('DEMO PASS')

    def verify_pin(self, pin):
        self.require(1)
        if not hmac.compare_digest(self.hash_pin(pin), self.pin_hash):
            self.tries += 1
            if self.tries >= 3: self.reject('Three incorrect PIN attempts.')
            raise ValueError(f'Incorrect PIN. {3-self.tries} attempts remain. Demo PIN: 246810')
        self.advance('LOCAL PASS')

    def issue_otp(self):
        self.require(2)
        self.otp = f'{secrets.randbelow(1000000):06d}'
        self.otp_deadline = time.monotonic() + 60
        return self.otp

    def verify_otp(self, value):
        self.require(2)
        if self.otp is None: raise ValueError('Generate the demo OTP first.')
        if time.monotonic() > self.otp_deadline:
            raise ValueError('OTP expired. Generate a new one.')
        if not hmac.compare_digest(value, self.otp):
            self.otp_tries += 1
            if self.otp_tries >= 3: self.reject('Three incorrect OTP attempts.')
            raise ValueError(f'Incorrect OTP. {3-self.otp_tries} attempts remain.')
        self.otp = None
        self.advance('LOCAL PASS')

    def _local_only(self):
        if self.gateway is not None:
            raise ValueError('API mode: the local payment path is disabled. Use the API steps.')

    def encrypt(self):
        self._local_only()
        self.require(7)
        self.packet, self.intent, elapsed = self.lab.prepare(self.recipient, self.amount, self.contact_id, self.note)
        return elapsed

    def confirm(self):
        self._local_only()
        self.require(7)
        if self.packet is None: raise ValueError('Encrypt the payment first.')
        result = self.lab.confirm(self.packet)
        self.packet = None
        self.stage = 8
        return result

    def tamper(self):
        self._local_only()
        self.require(7)
        if self.packet is None: raise ValueError('Encrypt the payment first.')
        return self.lab.confirm(tampered(self.packet))

    # ---- v17: final step through the REST gateway -------------------------------------------
    # Presentation buttons (e.g. "Genuine speaker scenario") never create evidence. Only
    # record_voice_evidence (real model scores) and record_device_verified (app-checked WebAuthn)
    # can feed the API, and challenge_verified is never sent: the API alone establishes it.

    def record_voice_evidence(self, scores, config):
        self.require(0)
        self._consent_cached_check()  # uses the status fetched by consent_gate just before scoring; no network here
        import evidence
        self.voice_evidence = evidence.voice_scores(scores, config)
        self.channel = evidence.channel_for(config)
        return self.voice_evidence

    def record_device_verified(self):
        self.require(4)
        self.device_verified = True

    def _need_gateway(self):
        if self.gateway is None:
            raise ValueError('No API gateway is configured.')

    def _destination(self):
        if not self.contact_id:
            raise ValueError('API mode needs a saved recipient account with a payment ID.')
        from contacts import resolve
        return resolve(self.contact_id).payment_id

    def _guard(self, fn, *args):
        from gateway_bridge import GatewayUnavailable, GatewayRejected
        try:
            return fn(*args)
        except GatewayUnavailable as exc:
            raise ValueError(str(exc) + ' There is no local fallback.') from None
        except GatewayRejected as exc:
            raise ValueError('API refused: ' + str(exc)) from None

    # ---- v17.1: biometric privacy consent --------------------------------------------------------
    # The gateway is the authority. The desktop asks before it captures or sends voice evidence, fails closed on an
    # outage, and throws recorded evidence away when consent is no longer valid.
    NEEDED = ('voice_verification', 'anti_spoofing')

    def _missing_consent(self, status):
        if not status or not status.get('enforced'):
            return []
        return [p for p in self.NEEDED if not status.get('purposes', {}).get(p)]

    def _consent_cached_check(self):
        missing = self._missing_consent(self.consent)
        if self.gateway is not None and missing:
            raise ValueError('Consent needed for: %s. Open Privacy & consent first.' % ', '.join(missing))

    def consent_refresh(self):
        self._need_gateway()
        self.consent = self._guard(self.gateway.consent_status)
        return self.consent

    def consent_gate(self):
        """Ask the gateway right now. Raises if biometric consent is enforced and missing. Network call: run it in the background."""
        status = self.consent_refresh()
        missing = self._missing_consent(status)
        if missing:
            self.voice_evidence = None
            raise ValueError('Consent needed for: %s. Open Privacy & consent and agree before using your voice.' % ', '.join(missing))
        return status

    def consent_grant(self):
        self._need_gateway()
        self.consent = self._guard(self.gateway.grant_consent)
        return self.consent

    def consent_withdraw(self):
        self._need_gateway()
        self.voice_evidence = None  # data minimisation: evidence recorded under the old consent is discarded
        self.consent = self._guard(self.gateway.withdraw_consent)
        return self.consent

    def consent_erase(self):
        self._need_gateway()
        self.voice_evidence = None
        self.consent = self._guard(self.gateway.erase_data)
        return self.consent

    @staticmethod
    def describe_consent(status):
        if not status:
            return 'Consent status not checked yet.'
        if not status.get('enforced'):
            return 'This gateway does not enforce biometric consent (lab setting).'
        names = {'voice_verification': 'voice verification', 'anti_spoofing': 'anti-spoofing'}
        return 'Consent: ' + '; '.join('%s %s' % (names[p], 'GIVEN' if status['purposes'].get(p) else 'NOT GIVEN')
                                       for p in ('voice_verification', 'anti_spoofing'))

    def api_submit(self, hour=None):
        from evidence import build_context
        from gateway_bridge import check_echo, IntentMismatch, new_idempotency_key
        self.require(7); self._need_gateway()
        if self.api: raise ValueError('Already submitted. Use the status step.')
        if self.voice_evidence is not None:
            self.consent_gate()  # recorded evidence is only sent while consent is still valid
        destination = self._destination()
        ctx = build_context(self.voice_evidence, self.device_verified, self.channel,
                            time.localtime().tm_hour if hour is None else hour)
        self.api_idem = self.api_idem or new_idempotency_key()  # a retry after an outage replays, never duplicates
        r = self._guard(self.gateway.create, self.recipient, destination, self.amount, self.note, ctx, self.api_idem)
        if r.get('status') == 'declined':
            self.reject('Risk engine declined: ' + '; '.join(r.get('risk', {}).get('reasons', [])) + '.')
        try: check_echo(r, self.recipient, destination, self.amount)
        except IntentMismatch as exc: self.reject(str(exc))
        self.api = {'id': r['id'], 'digest': r['digest'], 'step_up': bool(r['step_up_required']),
                    'challenge': None, 'challenge_ok': False, 'risk': r['risk']}
        return r

    # ---- v17.2: device verified by the gateway, not claimed by the desktop -----------------------
    # `authenticate(kind, public_key)` talks to the customer's authenticator: kind is 'create' or 'get', public_key is the
    # WebAuthn options dict from the gateway, and it returns the WebAuthn response dict. On Windows that is device_auth; in
    # tests it is a software authenticator.
    def api_device_register(self, authenticate):
        self._need_gateway()
        o = self._guard(self.gateway.device_register_begin)
        response = authenticate('create', o['publicKey'])
        return self._guard(self.gateway.device_register_complete, o['session'], response)

    def api_device_verify(self, authenticate):
        from device_gateway import challenge_for
        from fido2.utils import websafe_decode
        self.require(7); self._need_gateway()
        if not self.api: raise ValueError('Submit to the API first.')
        o = self._guard(self.gateway.device_assertion_begin, self.api['id'])
        if o.get('digest') != self.api['digest'] or websafe_decode(o['publicKey']['challenge']) != \
                challenge_for(o['digest'], bytes.fromhex(o['nonce'])):
            self.reject('The device challenge does not commit to the payment you reviewed.')
        response = authenticate('get', o['publicKey'])
        r = self._guard(self.gateway.device_assertion_complete, self.api['id'], o['session'], response)
        self.api['device_ok'] = True; self.api['challenge_ok'] = True  # the gateway accepted the signature
        return r

    def api_challenge(self, lang='en'):
        self.require(7)
        if not self.api or not self.api['step_up']: raise ValueError('No spoken challenge is required.')
        c = self._guard(self.gateway.challenge, self.api['id'], lang)
        self.api['challenge'] = c['challenge_id']
        return c['spoken_form'], c['expires_in']

    def api_verify_challenge(self, transcript):
        self.require(7)
        if not self.api or not self.api['challenge']: raise ValueError('Request a spoken challenge first.')
        cid, self.api['challenge'] = self.api['challenge'], None  # one attempt per challenge
        ok = bool(self._guard(self.gateway.verify_challenge, self.api['id'], cid, transcript)['verified'])
        self.api['challenge_ok'] = ok
        return ok

    def api_status(self):
        self.require(7)
        if not self.api: raise ValueError('Submit to the API first.')
        r = self._guard(self.gateway.status, self.api['id'])
        if r.get('digest') != self.api['digest']:
            self.reject('The API reports different payment details than you reviewed.')
        return r['status']

    def api_confirm(self):
        self.require(7)
        if not self.api: raise ValueError('Submit to the API first.')
        if self.api['step_up'] and not self.api['challenge_ok']:
            raise ValueError('Complete the spoken challenge first.')
        result = self._guard(self.gateway.confirm, self.api['id'], self.api['digest'])
        self.receipt = result
        self.stage = 8
        return result
