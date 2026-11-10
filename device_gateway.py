"""Gateway-side WebAuthn (FIDO2) verification of customer devices, bound to one transaction (To-Do B8, control C06).

Why: until v17.2 the API trusted a client claim `device_bound: true`. Now the gateway itself verifies a WebAuthn
assertion whose challenge commits to the transaction digest, so a signature proves that this registered device approved
this exact payment. It runs on any OS: the customer's own device (phone, passkey, security key) does the signing, and this
module only verifies, so the old Windows-only restriction no longer applies to the server.

What it checks
  * registration: origin, challenge, RP id hash, user present, user verified, and (when trust roots are supplied) the
    attestation statement and its certificate chain. Attestation is OPTIONAL by default and reported per credential as
    'attested' or 'unattested'. Set require_attested=True to refuse unattested devices.
  * assertion: origin, challenge (= SHA-256 of a fixed label, the transaction digest and a one-time nonce), RP id hash,
    user present, user verified, signature, and a strictly increasing signature counter (clone detection) when the
    authenticator keeps one. Each begin() state is single-use and expires.

What it does NOT do
  * It ships no vendor trust roots. Real hardware attestation needs roots from the FIDO Metadata Service or the vendor.
  * It does not check certificate revocation, authenticator certification level or FIDO MDS status.
  * Passkeys that sync between devices report counter 0; they are accepted, but clone detection is then not possible.
"""
import hashlib
import secrets
import threading
import time

from cryptography import x509
from fido2.attestation import (AttestationVerifier, UntrustedAttestation, verify_x509_chain)
from fido2.attestation.base import InvalidAttestation
from fido2.server import Fido2Server
from fido2.webauthn import (AttestedCredentialData, AuthenticationResponse, PublicKeyCredentialRpEntity,
                            PublicKeyCredentialUserEntity, RegistrationResponse)

LABEL = b'QuantaVoice txn v1|'
MAX_CREDENTIALS = 5


class DeviceError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code = status, code


def challenge_for(digest_hex, nonce):
    """What the device signs over. The digest is the payment's SHA-256 digest from the authorization."""
    return hashlib.sha256(LABEL + bytes.fromhex(digest_hex) + nonce).digest()


class _Verifier(AttestationVerifier):
    """Accepts only attestation whose certificate chain ends in one of OUR roots. Never trusts 'none' or self attestation."""

    def __init__(self, roots, clock):
        super().__init__()
        self.roots, self.clock = list(roots), clock

    def ca_lookup(self, attestation_result, auth_data):
        for root in self.roots:
            try:
                verify_x509_chain(list(attestation_result.trust_path) + [root])
                return root
            except Exception:
                continue
        return None

    def verify_attestation(self, attestation_object, client_data_hash):
        # Re-implemented so an empty trust path (none / self attestation) can never pass as "trusted".
        from fido2.attestation import UnsupportedAttestation
        verifier = UnsupportedAttestation(attestation_object.fmt)
        for at in self._attestation_types:
            if getattr(at, 'FORMAT', None) == attestation_object.fmt:
                verifier = at
                break
        result = verifier.verify(attestation_object.att_stmt, attestation_object.auth_data, client_data_hash)
        if not result.trust_path:
            raise UntrustedAttestation('Attestation carries no certificate chain.')
        leaf = x509.load_der_x509_certificate(result.trust_path[0])
        import datetime
        now = datetime.datetime.fromtimestamp(self.clock(), datetime.timezone.utc)
        if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
            raise UntrustedAttestation('Attestation certificate is not valid now.')
        if self.ca_lookup(result, attestation_object.auth_data) is None:
            raise UntrustedAttestation('No trusted root for this authenticator.')


class DeviceVerifier:
    def __init__(self, rp_id='localhost', rp_name='QuantaVoice', origins=('https://localhost',), trust_roots=(),
                 require_attested=False, ttl=120, clock=time.time):
        if require_attested and not trust_roots:
            raise ValueError('require_attested needs trust_roots (DER bytes).')
        self.origins, self.ttl, self.clock, self.require = tuple(origins), ttl, clock, require_attested
        self.lock = threading.RLock()
        self.sessions, self.devices = {}, {}   # session -> dict ; (key_id, ref) -> [credential records]
        verifier = _Verifier(trust_roots, clock) if trust_roots else None
        self.server = Fido2Server(PublicKeyCredentialRpEntity(id=rp_id, name=rp_name),
                                  attestation='direct' if verifier else None,
                                  verify_origin=lambda o: o in self.origins, verify_attestation=verifier)

    # ---- helpers ----
    def _new_session(self, **data):
        token = secrets.token_urlsafe(24)
        with self.lock:
            now = self.clock()
            self.sessions = {k: v for k, v in self.sessions.items() if v['expires'] > now}  # drop stale
            self.sessions[token] = dict(data, expires=now + self.ttl)
        return token

    def _take(self, token, kind, key_id, ref):
        with self.lock:
            s = self.sessions.pop(token, None) if isinstance(token, str) else None  # single use, even on failure
        if not s or s['kind'] != kind or s['expires'] <= self.clock() or (s['key_id'], s['ref']) != (key_id, ref):
            raise DeviceError(400, 'invalid_session', 'Unknown, used or expired session.')
        return s

    def credentials(self, key_id, ref):
        return list(self.devices.get((key_id, ref), []))

    # ---- registration ----
    def register_begin(self, key_id, ref):
        existing = self.credentials(key_id, ref)
        if len(existing) >= MAX_CREDENTIALS:
            raise DeviceError(409, 'too_many_devices', 'Remove a device before adding another.')
        user = PublicKeyCredentialUserEntity(id=hashlib.sha256(('qv|%s|%s' % (key_id, ref)).encode()).digest(),
                                             name=ref, display_name='QuantaVoice customer')
        options, state = self.server.register_begin(
            user, [r['data'] for r in existing] or None, user_verification='required')
        session = self._new_session(kind='register', key_id=key_id, ref=ref, state=state)
        return {'session': session, 'publicKey': dict(options.public_key)}

    def register_complete(self, key_id, ref, session, response):
        s = self._take(session, 'register', key_id, ref)
        try:
            auth = self.server.register_complete(s['state'], response)
        except InvalidAttestation as exc:  # none / self / bad signature / untrusted chain, whenever roots are configured
            raise DeviceError(400, 'attestation_untrusted', 'The device attestation could not be trusted.') from exc
        except Exception as exc:
            raise DeviceError(400, 'device_verification_failed', 'Device registration could not be verified.') from exc
        level = 'attested' if self.server.attestation else 'unattested'
        if self.require and level != 'attested':
            raise DeviceError(400, 'attestation_required', 'Only attested devices are accepted.')
        cred = auth.credential_data
        with self.lock:
            if any(r['data'].credential_id == cred.credential_id for recs in self.devices.values() for r in recs):
                raise DeviceError(409, 'device_exists', 'This credential is already registered.')
            self.devices.setdefault((key_id, ref), []).append(
                {'data': cred, 'counter': auth.counter, 'level': level, 'created': self.clock()})
        return {'registered': True, 'attestation': level, 'devices': len(self.credentials(key_id, ref))}

    def remove_all(self, key_id, ref):
        with self.lock:
            return len(self.devices.pop((key_id, ref), []))

    # ---- assertion bound to one transaction ----
    def assertion_begin(self, key_id, ref, auth_id, digest):
        creds = self.credentials(key_id, ref)
        if not creds:
            raise DeviceError(404, 'no_device', 'No device is registered for this customer.')
        if not isinstance(digest, str) or len(digest) != 64:
            raise DeviceError(400, 'invalid_digest', 'Bad transaction digest.')
        nonce = secrets.token_bytes(16)
        options, state = self.server.authenticate_begin([r['data'] for r in creds], user_verification='required',
                                                        challenge=challenge_for(digest, nonce))
        session = self._new_session(kind='assert', key_id=key_id, ref=ref, state=state, auth_id=auth_id)
        return {'session': session, 'publicKey': dict(options.public_key), 'digest': digest, 'nonce': nonce.hex()}

    def assertion_complete(self, key_id, ref, auth_id, session, response):
        s = self._take(session, 'assert', key_id, ref)
        if s['auth_id'] != auth_id:
            raise DeviceError(400, 'invalid_session', 'Session belongs to another authorization.')
        creds = self.credentials(key_id, ref)
        try:
            used = self.server.authenticate_complete(s['state'], [r['data'] for r in creds], response)
            count = AuthenticationResponse.from_dict(response).response.authenticator_data.counter
        except Exception as exc:
            raise DeviceError(400, 'device_verification_failed', 'Device assertion could not be verified.') from exc
        with self.lock:
            rec = next(r for r in self.devices[(key_id, ref)] if r['data'].credential_id == used.credential_id)
            if (count or rec['counter']) and count <= rec['counter']:
                raise DeviceError(400, 'device_verification_failed', 'Device assertion could not be verified.')  # clone/replay
            rec['counter'] = count
        return {'verified': True, 'attestation': rec['level'], 'user_verified': True}
