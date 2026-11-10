"""Development PKI for the API lab: a throw-away CA, a server certificate and a client certificate.

LAB ONLY. These keys are generated on this machine, are not issued by a public or bank CA and are not a substitute for a
reviewed production TLS setup (certificate lifecycle, revocation, HSM-held keys, cipher policy, hybrid post-quantum groups).
"""
import datetime
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'QuantaVoice dev'), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, data, private=False):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if private and os.name != 'nt':
        os.chmod(path, 0o600)


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _issue(ca_key, ca_cert, subject_cn, san, usage, days):
    key = _key(); now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(subject_cn)).issuer_name(ca_cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return key, b.sign(ca_key, hashes.SHA256())


def make_dev_pki(directory, hosts=('localhost', '127.0.0.1', '::1'), days=30, client_name='lab-client'):
    """Write ca.pem, server.pem/server.key, client.pem/client.key into `directory`. Returns a dict of paths."""
    d = Path(directory)
    ca_key = _key(); now = datetime.datetime.now(datetime.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(_name('QuantaVoice dev CA')).issuer_name(_name('QuantaVoice dev CA'))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    san = []
    for h in hosts:
        try: san.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError: san.append(x509.DNSName(h))
    skey, scert = _issue(ca_key, ca, hosts[0], san, ExtendedKeyUsageOID.SERVER_AUTH, days)
    ckey, ccert = _issue(ca_key, ca, client_name, None, ExtendedKeyUsageOID.CLIENT_AUTH, days)
    paths = {'ca': d / 'ca.pem', 'cert': d / 'server.pem', 'key': d / 'server.key', 'client_cert': d / 'client.pem',
             'client_key': d / 'client.key'}
    _write(paths['ca'], ca.public_bytes(serialization.Encoding.PEM))
    _write(paths['cert'], scert.public_bytes(serialization.Encoding.PEM)); _write(paths['key'], _pem_key(skey), True)
    _write(paths['client_cert'], ccert.public_bytes(serialization.Encoding.PEM)); _write(paths['client_key'], _pem_key(ckey), True)
    return {k: str(v) for k, v in paths.items()}


def openssl_note():
    """Honest statement of what this machine's TLS library is. Hybrid post-quantum key exchange is not verified here."""
    major_minor = ssl.OPENSSL_VERSION_INFO[:2]
    pq = 'X25519MLKEM768 is a default TLS 1.3 group from OpenSSL 3.5, so it may be negotiated; not verified by this code' \
        if major_minor >= (3, 5) else 'OpenSSL older than 3.5: no hybrid post-quantum key exchange in TLS'
    return '%s; %s' % (ssl.OPENSSL_VERSION, pq)
