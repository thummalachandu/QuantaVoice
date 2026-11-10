import unittest, tempfile, json
from pathlib import Path
import numpy as np
from voice_command import parse_payment
from contacts import add_contact,matches,CONTACTS
from research import channel,eer,tandem_metrics

class ResearchTests(unittest.TestCase):
    def test_multilingual_and_new_name(self):
        for text,expected in [('Pay 5000 rupees to Chandu Tummala',('Chandu Tummala','5000.00')),
             ('चंदू को पांच हजार रुपये भेजो',('चंदू','5000.00')),
             ('చందు కి ఐదు వేల రూపాయలు పంపు',('చందు','5000.00')),
             ('चंदू को ५०० रुपये भेजो',('चंदू','500.00'))]:
            self.assertEqual(parse_payment(text),expected)
    def test_new_contact_alias_and_duplicate(self):
        n=len(CONTACTS)
        try:
            c=add_contact('Chandu','1234567890','chandu.test@demo',('చందు','चंदू'),persist=False)
            self.assertEqual(matches('చందు'),[c]); self.assertEqual(c.phone,'******7890')
            with self.assertRaises(ValueError): add_contact('Another','1234','chandu.test@demo',persist=False)
        finally: del CONTACTS[n:]
    def test_telephony_length_and_loss(self):
        x=(.3*np.sin(2*np.pi*440*np.arange(32000)/16000)).astype(np.float32)
        for codec in ('pcm8','alaw','ulaw'):
            y=channel(x,16000,codec,1)
            self.assertEqual(len(y),16000); self.assertTrue(np.isfinite(y).all())
            self.assertGreater(float(np.mean((y-x[:16000])**2)),0)
        with self.assertRaises(ValueError): channel(x,16000,'alaw',3)
    def test_metrics_and_missing_classes(self):
        self.assertEqual(eer([.9,.8,.2,.1],[1,1,0,0])['eer_nearest'],0)
        with self.assertRaises(ValueError): eer([1,2],[1,1])
        rows=[{'label':'target','asv':1.,'cm':1.},{'label':'nontarget','asv':0.,'cm':1.},
              {'label':'spoof','asv':1.,'cm':0.}]
        cost={'prior':{'target':.9,'nontarget':.05,'spoof':.05},'cost':{'target':1.,'nontarget':10.,'spoof':10.}}
        result=tandem_metrics(rows,.5,.5,cost)
        self.assertEqual(result['joint_cost'],0); self.assertEqual(result['normalized_tdcf'],0)
    def test_device_rejects_nonwindows(self):
        import types
        from unittest import mock
        import device_auth
        from device_auth import DeviceAuth
        # Runs on every OS: pretend to be a non-Windows host so the guard is exercised without hardware.
        with mock.patch.object(device_auth, 'os', types.SimpleNamespace(name='posix')):
            with self.assertRaises(RuntimeError): DeviceAuth().client()
    def test_webauthn_rejects_wrong_challenge(self):
        from fido2.server import Fido2Server
        from fido2.webauthn import CollectedClientData,AuthenticatorData,AttestedCredentialData,AuthenticationResponse,AuthenticatorAssertionResponse
        from fido2.cose import ES256
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        import hashlib
        private=ec.generate_private_key(ec.SECP256R1())
        credential=AttestedCredentialData.create(bytes(16),b'local-test-credential',ES256.from_cryptography_key(private.public_key()))
        server=Fido2Server({'id':'localhost','name':'test'})
        opts,state=server.authenticate_begin([credential],user_verification='required')
        client=CollectedClientData.create('webauthn.get',opts.public_key.challenge,'https://localhost')
        auth=AuthenticatorData.create(hashlib.sha256(b'localhost').digest(),AuthenticatorData.FLAG.UP|AuthenticatorData.FLAG.UV,1)
        signature=private.sign(bytes(auth)+client.hash,ec.ECDSA(hashes.SHA256()))
        response=AuthenticationResponse(raw_id=credential.credential_id,response=AuthenticatorAssertionResponse(client_data=client,authenticator_data=auth,signature=signature))
        server.authenticate_complete(state,[credential],response)
        _,other_state=server.authenticate_begin([credential],user_verification='required')
        with self.assertRaises(ValueError): server.authenticate_complete(other_state,[credential],response)

if __name__=='__main__': unittest.main()
