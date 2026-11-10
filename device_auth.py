"""Actual Windows WebAuthn requests and local assertion verification.
This verifies a local demo credential, not a bank customer or biometric modality.
"""
from pathlib import Path
import os, json, secrets, hashlib, time

class DeviceAuth:
    def __init__(self):
        from fido2.server import Fido2Server
        self.server=Fido2Server({'id':'localhost','name':'QuantaVoice local research'})
        self.server.timeout=60000
        self.path=Path(__file__).resolve().parent/'device_credential.json'
    def client(self):
        if os.name!='nt': raise RuntimeError('Live WebAuthn requires Windows 10/11 and a configured authenticator.')
        from fido2.client import DefaultClientDataCollector
        from fido2.client.windows import WindowsClient
        if not WindowsClient.is_available(): raise RuntimeError('Windows WebAuthn is unavailable.')
        return WindowsClient(DefaultClientDataCollector('https://localhost'))
    def register(self):
        from fido2.webauthn import PublicKeyCredentialUserEntity
        if self.path.exists(): raise ValueError('A local credential is already registered.')
        user=PublicKeyCredentialUserEntity(id=secrets.token_bytes(32),name='local-research-user',display_name='QuantaVoice demo user')
        options,state=self.server.register_begin(user,user_verification='required')
        response=self.client().make_credential(options.public_key)
        auth=self.server.register_complete(state,response)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.path.write_text(json.dumps({'credential':bytes(auth.credential_data).hex(),'counter':auth.counter}))
        return 'Registered a local demo credential. Customer identity has not been established.'
    def verify(self,intent):
        from fido2.webauthn import AttestedCredentialData
        if not self.path.exists(): raise ValueError('Register a local device credential first.')
        saved=json.loads(self.path.read_text()); credential=AttestedCredentialData(bytes.fromhex(saved['credential']))
        challenge=hashlib.sha256(secrets.token_bytes(32)+json.dumps(intent,sort_keys=True).encode()).digest()
        options,state=self.server.authenticate_begin([credential],user_verification='required',challenge=challenge)
        started=time.monotonic()
        selection=self.client().get_assertion(options.public_key)
        response=selection.get_response(0)
        if time.monotonic()-started>60: raise ValueError('Device assertion expired.')
        self.server.authenticate_complete(state,[credential],response)
        count=response.response.authenticator_data.counter
        if saved['counter'] and count and count<=saved['counter']: raise ValueError('Authenticator counter did not advance.')
        saved['counter']=count; self.path.write_text(json.dumps(saved))
        return 'WebAuthn signature and required user verification verified; biometric modality is not asserted.'


def gateway_authenticator(origin='https://localhost'):
    """Authenticator callable for Flow.api_device_register / api_device_verify (v17.2).

    The gateway verifies; this only asks the customer's own authenticator to sign. Windows 10/11 with Windows Hello or a
    security key. Not tested on real hardware by the author (the build environment has none). `origin` must be one of the
    origins the gateway was started with (api_lab.py --webauthn-origin).
    """
    def run(kind, public_key):
        if os.name != 'nt': raise RuntimeError('Live WebAuthn from this app needs Windows 10/11 and an authenticator.')
        from fido2.client import DefaultClientDataCollector
        from fido2.client.windows import WindowsClient
        from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions
        if not WindowsClient.is_available(): raise RuntimeError('Windows WebAuthn is unavailable.')
        client = WindowsClient(DefaultClientDataCollector(origin))
        if kind == 'create':
            return dict(client.make_credential(PublicKeyCredentialCreationOptions.from_dict(public_key)))
        selection = client.get_assertion(PublicKeyCredentialRequestOptions.from_dict(public_key))
        return dict(selection.get_response(0))
    return run
