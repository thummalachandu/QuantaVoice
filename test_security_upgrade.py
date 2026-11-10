import unittest,json
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.ml_kem_768 import encrypt
from core import Lab,CONTEXT,key
from security_inventory import inventory
class SecurityUpgradeTests(unittest.TestCase):
    def test_signature_tamper(self):
        lab=Lab(); p,_,_=lab.prepare('Chandu','1'); signature=bytearray(p.signature); signature[0]^=1
        with self.assertRaises(ValueError): lab.confirm(replace(p,signature=bytes(signature)))
        self.assertEqual(lab.balance,5000000)
        lab.confirm(p)
    def test_missing_signature(self):
        lab=Lab(); p,_,_=lab.prepare('Chandu','1')
        with self.assertRaises(ValueError): lab.confirm(replace(p,signature=b''))
    def test_wrong_signer(self):
        lab=Lab(); other=Lab(); p,_,_=lab.prepare('Chandu','1'); q,_,_=other.prepare('Chandu','1')
        with self.assertRaises(ValueError): lab.confirm(replace(p,signature=q.signature))
    def test_reencrypted_changed_amount(self):
        lab=Lab(); p,intent,_=lab.prepare('Chandu','1'); intent['paise']=200
        kem,secret=encrypt(lab.public)
        cipher=AESGCM(key(secret)).encrypt(p.nonce,json.dumps(intent,sort_keys=True).encode(),CONTEXT)
        with self.assertRaises(ValueError): lab.confirm(replace(p,kem=kem,payload=cipher))
        self.assertEqual(lab.balance,5000000)
    def test_duplicate_concurrent_confirm(self):
        lab=Lab(); p,_,_=lab.prepare('Chandu','1')
        def confirm(_):
            try: lab.confirm(p); return True
            except ValueError: return False
        with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(confirm,range(8)))
        self.assertEqual(sum(results),1); self.assertEqual(lab.balance,4999900)
    def test_rotation_invalidates_old_payment(self):
        lab=Lab(); p,_,_=lab.prepare('Chandu','1'); old=lab.key_id(); lab.rotate_keys()
        self.assertNotEqual(old,lab.key_id()); self.assertFalse(lab.pending)
        with self.assertRaises((ValueError,InvalidTag)): lab.confirm(p)
        self.assertEqual(lab.balance,5000000)
        q,_,_=lab.prepare('Chandu','2'); lab.confirm(q); self.assertEqual(lab.balance,4999800)
    def test_new_intent_invalidates_old(self):
        lab=Lab(); p,_,_=lab.prepare('Chandu','1'); q,_,_=lab.prepare('Chandu','2')
        with self.assertRaises(ValueError): lab.confirm(p)
        lab.confirm(q)
    def test_inventory_does_not_claim_external_services(self):
        report=inventory()
        self.assertFalse(report['real_payments']); self.assertFalse(report['key_management']['hsm'])
        self.assertTrue(all(v=='not integrated or verified' for v in report['external'].values()))
        self.assertEqual(len(report['source_sha256']),64)
