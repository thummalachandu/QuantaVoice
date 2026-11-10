"""Software WebAuthn authenticator for TESTS and demos. It is not a security device: the private key lives in memory.
Produces the same JSON a browser's PublicKeyCredential.toJSON() would, so the gateway code path is the real one."""
import datetime
import hashlib
import json
import os
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fido2 import cbor
from fido2.utils import websafe_decode, websafe_encode

FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40


def make_ca(name='Test Attestation Root', days=3650, now=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return key, cert


def make_leaf(ca_key, ca_cert, aaguid, valid_days=365, start_offset_days=-1):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, 'SE'),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Vendor'),
                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Authenticator Attestation'),
                         x509.NameAttribute(NameOID.COMMON_NAME, 'Test Authenticator')])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + datetime.timedelta(days=start_offset_days))
            .not_valid_after(now + datetime.timedelta(days=start_offset_days + valid_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4'),
                                                      b'\x04\x10' + aaguid), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def _cose(pub):
    n = pub.public_numbers()
    return cbor.encode({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, 'big'), -3: n.y.to_bytes(32, 'big')})


class SoftKey:
    def __init__(self, origin='https://localhost', rp_id='localhost', fmt='none', ca=None, aaguid=None,
                 user_verified=True, counter=True, leaf_days=365, leaf_start=-1):
        self.origin, self.rp_id, self.fmt = origin, rp_id, fmt
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.aaguid = aaguid or os.urandom(16)
        self.uv, self.use_counter, self.count = user_verified, counter, 0
        self.leaf = self.ca = None
        if ca:
            self.ca = ca
            self.leaf = make_leaf(ca[0], ca[1], self.aaguid, leaf_days, leaf_start)

    def _client_data(self, kind, challenge_b64):
        return json.dumps({'type': kind, 'challenge': challenge_b64, 'origin': self.origin, 'crossOrigin': False}).encode()

    def _flags(self, extra=0):
        return FLAG_UP | (FLAG_UV if self.uv else 0) | extra

    def __call__(self, kind, public_key, **tamper):
        return self.create(public_key, **tamper) if kind == 'create' else self.get(public_key, **tamper)

    def create(self, options, **tamper):
        cdj = self._client_data('webauthn.create', options['challenge'])
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        cred = self.aaguid + struct.pack('>H', len(self.cred_id)) + self.cred_id + _cose(self.key.public_key())
        auth = rp_hash + bytes([self._flags(FLAG_AT)]) + struct.pack('>I', 0) + cred
        h = hashlib.sha256(cdj).digest()
        if self.fmt == 'none':
            stmt = {}
        elif self.fmt == 'packed-self':
            stmt = {'alg': -7, 'sig': self.key.sign(auth + h, ec.ECDSA(hashes.SHA256()))}
        else:  # packed with x5c
            stmt = {'alg': -7, 'sig': self.leaf[0].sign(auth + h, ec.ECDSA(hashes.SHA256())),
                    'x5c': [self.leaf[1].public_bytes(serialization.Encoding.DER)]}
        fmt = 'none' if self.fmt == 'none' else 'packed'
        att = cbor.encode({'fmt': fmt, 'attStmt': stmt, 'authData': auth})
        return {'id': websafe_encode(self.cred_id), 'rawId': websafe_encode(self.cred_id), 'type': 'public-key',
                'response': {'clientDataJSON': websafe_encode(cdj), 'attestationObject': websafe_encode(att)},
                'clientExtensionResults': {}}

    def get(self, options, **tamper):
        cdj = self._client_data('webauthn.get', tamper.get('challenge', options['challenge']))
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        if self.use_counter:
            self.count = tamper.get('counter', self.count + 1)
        auth = rp_hash + bytes([self._flags()]) + struct.pack('>I', self.count if self.use_counter else 0)
        sig = self.key.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {'id': websafe_encode(self.cred_id), 'rawId': websafe_encode(self.cred_id), 'type': 'public-key',
                'response': {'clientDataJSON': websafe_encode(cdj), 'authenticatorData': websafe_encode(auth),
                             'signature': websafe_encode(sig)}, 'clientExtensionResults': {}}
