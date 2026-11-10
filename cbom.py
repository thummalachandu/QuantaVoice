"""CycloneDX 1.6 Cryptography Bill of Materials plus an honest connection/compliance map.

Lists the algorithms this project actually uses so a bank's security team can import it into
CBOM tooling. Library versions are read from the running environment. Assertions about
validation or certification are intentionally 'not claimed'.
"""
import json
import uuid
from datetime import datetime, timezone
from importlib import metadata

ALGORITHMS = [
    ('ML-KEM-768', 'kem', 'ML-KEM-768', '2.16.840.1.101.3.4.4.2', 'FIPS 203', 3, ['encapsulate', 'decapsulate']),
    ('ML-DSA-65', 'signature', 'ML-DSA-65', '2.16.840.1.101.3.4.3.18', 'FIPS 204', 3, ['sign', 'verify']),
    ('X25519', 'key-agree', 'X25519', '1.3.101.110', 'RFC 7748', 0, ['keygen', 'keyderive']),
    ('AES-256-GCM', 'ae', '256', '2.16.840.1.101.3.4.1.46', 'SP 800-38D', 5, ['encrypt', 'decrypt']),
    ('HKDF-SHA256', 'kdf', 'SHA-256', None, 'RFC 5869 / SP 800-56C', 2, ['keyderive']),
    ('SHA-256', 'hash', '256', '2.16.840.1.101.3.4.2.1', 'FIPS 180-4', 2, ['digest']),
    ('HMAC-SHA256', 'mac', 'SHA-256', '1.2.840.113549.2.9', 'FIPS 198-1', 2, ['tag']),
    ('scrypt', 'kdf', 'n=32768,r=8,p=1', None, 'RFC 7914', 0, ['keyderive']),
    # v17.2: classical algorithms used by customer-device verification and by transport security. Not quantum safe.
    ('ECDSA-P256 (WebAuthn ES256 and TLS certificates)', 'signature', 'secp256r1', '1.2.840.10045.4.3.2', 'FIPS 186-5 / WebAuthn L2', 0,
     ['sign', 'verify']),
    ('ECDHE (TLS 1.2/1.3 key exchange, library default)', 'key-agree', 'x25519 / secp256r1', None, 'RFC 8446 / RFC 5246', 0,
     ['keygen', 'keyderive']),
]


APP_VERSION = '17.3'  # single source for the CBOM; bump together with the changelog


def _version(pkg):
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return 'unknown'


def build_cbom():
    components = []
    for name, prim, param, oid, std, qlevel, funcs in ALGORITHMS:
        props = {'assetType': 'algorithm',
                 'algorithmProperties': {'primitive': prim, 'parameterSetIdentifier': param,
                                         'cryptoFunctions': funcs, 'nistQuantumSecurityLevel': qlevel}}
        if oid:
            props['oid'] = oid
        components.append({'type': 'cryptographic-asset', 'bom-ref': 'crypto/algorithm/' + name.lower(),
                           'name': name, 'description': 'Standard: ' + std, 'cryptoProperties': props})
    for pkg in ('pqcrypto', 'cryptography', 'numpy'):
        components.append({'type': 'library', 'bom-ref': 'lib/' + pkg, 'name': pkg, 'version': _version(pkg)})
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'serialNumber': 'urn:uuid:' + str(uuid.uuid4()),
            'version': 1,
            'metadata': {'timestamp': datetime.now(timezone.utc).isoformat(),
                         'component': {'type': 'application', 'name': 'QuantaVoice', 'version': APP_VERSION}},
            'components': components}


def quantum_readiness():
    return {'quantum_safe': ['ML-KEM-768', 'ML-DSA-65', 'AES-256-GCM', 'SHA-256', 'HMAC-SHA256', 'HKDF-SHA256'],
            'classical_only_vulnerable_to_large_quantum_computers': ['X25519 (kept only inside a hybrid with ML-KEM-768)'],
            'note': 'Levels follow NIST categories; this is a self-assessment, not a certification.'}


def compliance_map(provider_status):
    return [
        {'control': 'NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) algorithms', 'status': 'implemented via pqcrypto',
         'caveat': 'Library implementation is not FIPS 140-3 validated.'},
        {'control': 'Hybrid classical+PQ key establishment', 'status': 'implemented (application layer)',
         'caveat': 'The lab gateway now speaks TLS 1.2/1.3 and mutual TLS (v17.2) through OpenSSL, but hybrid X25519MLKEM768 is not '
                   'verified (needs OpenSSL 3.5 or newer and a reviewed production setup).'},
        {'control': 'Transport security (TLS / mTLS)', 'status': 'implemented (lab PKI)',
         'caveat': 'Lab certificates only. No production CA, revocation, HSM-held keys or independent review.'},
        {'control': 'Customer device verification (WebAuthn)', 'status': 'implemented (software authenticator tests)',
         'caveat': 'ES256 is classical, not post-quantum. No real hardware authenticator test, no FIDO MDS trust roots.'},
        {'control': 'Tamper-evident audit trail', 'status': 'implemented (hash chain + ML-DSA)',
         'caveat': 'Signing key is local; no WORM storage or key custody.'},
        {'control': 'NIST SP 800-90B-style entropy health tests', 'status': 'implemented (RCT, APT)',
         'caveat': 'Not a certified entropy source.'},
        {'control': 'ETSI GS QKD 014 key delivery', 'status': 'client adapter only', 'caveat': provider_status['qkd']},
        {'control': 'QRNG', 'status': 'adapter only', 'caveat': provider_status['qrng']},
        {'control': 'HSM / PKCS#11', 'status': 'not implemented', 'caveat': provider_status['hsm']},
        {'control': 'PCI DSS', 'status': 'not claimed', 'caveat': 'Tokenization is a simulated design demonstrator.'},
        {'control': 'ISO/IEC 27001', 'status': 'not claimed', 'caveat': 'Needs an organisation-level ISMS audit.'},
        {'control': 'Real identity verification of customers', 'status': 'not implemented',
         'caveat': 'Speaker evidence needs calibrated models and institutional review.'},
    ]


if __name__ == '__main__':
    print(json.dumps(build_cbom(), indent=2))
