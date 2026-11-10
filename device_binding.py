"""Server-side relying party for device-bound ML-DSA-65 keys (software passkey emulation).

Works on any OS (the existing fido2 path needs Windows). A device keeps its private key; the
server stores only the public key, issues a one-time challenge, and requires a signature over
the challenge, the exact transaction digest and a strictly increasing counter.
It does not prove biometric user verification or hardware attestation (software keys).
"""
import hashlib
import json
import secrets
import threading
import time

from pqcrypto.sign.ml_dsa_65 import generate_keypair, sign, verify

CONTEXT = b'QuantaVoice device assertion v1'


def _signed_bytes(rp_id, challenge, digest, counter):
    return CONTEXT + json.dumps({'rp': rp_id, 'challenge': challenge, 'digest': digest, 'counter': counter},
                                sort_keys=True, separators=(',', ':')).encode()


class DeviceAuthenticator:
    """Client side. Holds the private key and a monotonic counter."""

    def __init__(self, device_id):
        self.device_id = device_id
        self.public, self._private = generate_keypair()
        self.counter = 0

    def assert_intent(self, rp_id, challenge, digest):
        self.counter += 1
        sig = sign(self._private, _signed_bytes(rp_id, challenge, digest, self.counter))
        return {'device_id': self.device_id, 'counter': self.counter, 'signature': sig.hex()}


class DeviceRegistry:
    def __init__(self, rp_id='quantavoice.local', ttl=60, clock=time.monotonic):
        self.rp_id, self.ttl, self.clock = rp_id, ttl, clock
        self.lock = threading.Lock()
        self.devices, self.challenges = {}, {}

    def register(self, device_id, public_key):
        with self.lock:
            if device_id in self.devices:
                raise ValueError('Device already registered.')
            self.devices[device_id] = {'public': bytes(public_key), 'counter': 0,
                                       'fingerprint': hashlib.sha256(public_key).hexdigest()}
            return self.devices[device_id]['fingerprint']

    def begin(self, device_id, digest):
        with self.lock:
            if device_id not in self.devices:
                raise ValueError('Unknown device.')
            challenge = secrets.token_hex(32)
            self.challenges[(device_id, challenge)] = (digest, self.clock() + self.ttl)
            return challenge

    def complete(self, challenge, digest, assertion):
        device_id = assertion.get('device_id')
        with self.lock:
            saved = self.challenges.pop((device_id, challenge), None)  # one-time, even on failure
            device = self.devices.get(device_id)
            if not saved or not device or self.clock() >= saved[1] or saved[0] != digest:
                return False
            counter = assertion.get('counter')
            if not isinstance(counter, int) or counter <= device['counter']:
                return False  # cloned or replayed authenticator
            try:
                good = verify(device['public'], _signed_bytes(self.rp_id, challenge, digest, counter),
                              bytes.fromhex(assertion['signature']))
            except Exception:
                return False
            if good:
                device['counter'] = counter
            return bool(good)
