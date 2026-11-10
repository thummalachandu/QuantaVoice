import base64
import json
import tempfile
import threading
import unittest
import warnings
from pathlib import Path

import numpy as np

import api_gateway as api
import ccaas_connector as cc
import challenge_phrase
import device_binding
import payment_rails
import risk_engine
import sdk
import tokenization
from audit_log import AuditLog
from backend_store import BackendStore

GOOD = {'asv_score': 0.9, 'cm_score': 0.9, 'device_bound': True, 'challenge_verified': True, 'new_payee': False}


class Risk(unittest.TestCase):
    def test_clean_context_allows(self):
        self.assertEqual(risk_engine.RiskEngine().evaluate(100000, 'u', GOOD).action, 'allow')

    def test_missing_voice_evidence_never_allows(self):
        d = risk_engine.RiskEngine().evaluate(100, 'u', {'new_payee': False, 'device_bound': True, 'challenge_verified': True})
        self.assertEqual(d.action, 'step_up')
        self.assertEqual(set(d.missing_evidence), {'asv_score', 'cm_score'})

    def test_spoof_score_denies(self):
        d = risk_engine.RiskEngine().evaluate(100000, 'u', dict(GOOD, cm_score=0.1, asv_score=0.2))
        self.assertEqual(d.action, 'deny')

    def test_failed_challenge_is_heavy(self):
        d = risk_engine.RiskEngine().evaluate(100000, 'u', dict(GOOD, challenge_verified=False))
        self.assertIn(d.action, ('step_up', 'deny'))

    def test_velocity(self):
        clock = [1000.0]
        v = risk_engine.VelocityTracker(clock=lambda: clock[0]); r = risk_engine.RiskEngine(velocity=v)
        for _ in range(3):
            r.record_outcome('u', 100000)
        self.assertEqual(v.window('u', 3600)[0], 3)
        self.assertIn('3 or more authorizations in the last hour', r.evaluate(100, 'u', GOOD).reasons)
        clock[0] += 4000
        self.assertEqual(v.window('u', 3600)[0], 0)

    def test_bad_thresholds_rejected(self):
        with self.assertRaises(ValueError):
            risk_engine.RiskEngine(step_up_at=80, deny_at=50)


class Challenge(unittest.TestCase):
    def test_success_and_single_use(self):
        now = [0.0]; s = challenge_phrase.ChallengeService(clock=lambda: now[0])
        c = s.issue('d1')
        self.assertTrue(s.verify(c['challenge_id'], 'd1', c['spoken_form']))
        self.assertFalse(s.verify(c['challenge_id'], 'd1', c['spoken_form']))

    def test_wrong_digits_consume_attempt(self):
        s = challenge_phrase.ChallengeService(); c = s.issue('d1')
        self.assertFalse(s.verify(c['challenge_id'], 'd1', 'one two three four five six'))
        self.assertFalse(s.verify(c['challenge_id'], 'd1', c['spoken_form']))

    def test_bound_to_transaction_and_expiry(self):
        now = [0.0]; s = challenge_phrase.ChallengeService(ttl=45, clock=lambda: now[0])
        c = s.issue('d1'); self.assertFalse(s.verify(c['challenge_id'], 'other', c['spoken_form']))
        c = s.issue('d1'); now[0] = 46
        self.assertFalse(s.verify(c['challenge_id'], 'd1', c['spoken_form']))

    def test_languages_and_numerals(self):
        s = challenge_phrase.ChallengeService()
        for lang in challenge_phrase.DIGIT_WORDS:
            c = s.issue('d', lang); self.assertTrue(s.verify(c['challenge_id'], 'd', c['spoken_form']), lang)
        c = s.issue('d'); self.assertTrue(s.verify(c['challenge_id'], 'd', ' '.join(c['digits'])))

    def test_unknown_word_and_bad_language(self):
        s = challenge_phrase.ChallengeService(); c = s.issue('d')
        self.assertFalse(s.verify(c['challenge_id'], 'd', c['spoken_form'] + ' please'))
        with self.assertRaises(ValueError):
            s.issue('d', 'xx')

    def test_digits_not_trivial(self):
        s = challenge_phrase.ChallengeService()
        for _ in range(50):
            self.assertGreaterEqual(len(set(s.issue('d')['digits'])), 3)


class Device(unittest.TestCase):
    def setUp(self):
        self.now = [0.0]
        self.reg = device_binding.DeviceRegistry(clock=lambda: self.now[0])
        self.dev = device_binding.DeviceAuthenticator('phone-1')
        self.reg.register('phone-1', self.dev.public)

    def assertion(self, digest='dg'):
        ch = self.reg.begin('phone-1', digest)
        return ch, self.dev.assert_intent(self.reg.rp_id, ch, digest)

    def test_valid_assertion(self):
        ch, a = self.assertion(); self.assertTrue(self.reg.complete(ch, 'dg', a))

    def test_replay_rejected(self):
        ch, a = self.assertion(); self.assertTrue(self.reg.complete(ch, 'dg', a))
        self.assertFalse(self.reg.complete(ch, 'dg', a))

    def test_wrong_digest_or_expired(self):
        ch, a = self.assertion(); self.assertFalse(self.reg.complete(ch, 'other', a))
        ch, a = self.assertion(); self.now[0] = 100; self.assertFalse(self.reg.complete(ch, 'dg', a))

    def test_cloned_authenticator_counter_rejected(self):
        ch, a = self.assertion(); self.assertTrue(self.reg.complete(ch, 'dg', a))
        self.dev.counter = 0
        ch, a = self.assertion(); self.assertFalse(self.reg.complete(ch, 'dg', a))

    def test_other_device_key_rejected(self):
        rogue = device_binding.DeviceAuthenticator('phone-1')
        ch = self.reg.begin('phone-1', 'dg')
        self.assertFalse(self.reg.complete(ch, 'dg', rogue.assert_intent(self.reg.rp_id, ch, 'dg')))

    def test_duplicate_registration_and_unknown(self):
        with self.assertRaises(ValueError): self.reg.register('phone-1', self.dev.public)
        with self.assertRaises(ValueError): self.reg.begin('nobody', 'dg')


class Tokens(unittest.TestCase):
    PAN = '4111111111111111'

    def test_luhn(self):
        self.assertTrue(tokenization.luhn_valid(self.PAN))
        self.assertFalse(tokenization.luhn_valid('4111111111111112'))
        self.assertFalse(tokenization.luhn_valid('abc'))

    def test_token_properties(self):
        v = tokenization.TokenVault(); t = v.tokenize(self.PAN, 'm1')
        self.assertTrue(tokenization.luhn_valid(t)); self.assertNotEqual(t, self.PAN); self.assertTrue(t.startswith('9'))
        self.assertEqual(v.info(t)['last4'], '1111')
        self.assertNotIn(self.PAN, json.dumps(str(v.records)))

    def test_domain_restriction(self):
        v = tokenization.TokenVault(); t = v.tokenize(self.PAN, 'm1', 'dev1')
        self.assertEqual(v.detokenize(t, 'm1', 'dev1'), self.PAN)
        for args in (('m2', 'dev1'), ('m1', 'dev2'), ('m1', None)):
            with self.assertRaises(PermissionError): v.detokenize(t, *args)

    def test_cryptogram_single_use_and_bound(self):
        v = tokenization.TokenVault(); t = v.tokenize(self.PAN, 'm1')
        c = v.cryptogram(t, 'm1', 'digestA')
        self.assertFalse(v.verify_cryptogram(t, 'm1', 'digestB', c['counter'], c['cryptogram']))
        self.assertTrue(v.verify_cryptogram(t, 'm1', 'digestA', c['counter'], c['cryptogram']))
        self.assertFalse(v.verify_cryptogram(t, 'm1', 'digestA', c['counter'], c['cryptogram']))

    def test_revoke_and_invalid_pan(self):
        v = tokenization.TokenVault(); t = v.tokenize(self.PAN, 'm1'); v.revoke(t)
        with self.assertRaises(PermissionError): v.cryptogram(t, 'm1', 'd')
        with self.assertRaises(ValueError): v.tokenize('1234567890123456', 'm1')

    def test_mask(self):
        self.assertEqual(tokenization.mask(self.PAN), '************1111')


class Telephony(unittest.TestCase):
    def test_codecs_bit_exact_with_reference(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore'); import audioop
        pcm = np.arange(-32768, 32768, dtype=np.int16)
        self.assertEqual(cc.ulaw_encode(pcm), audioop.lin2ulaw(pcm.tobytes(), 2))
        self.assertEqual(cc.alaw_encode(pcm), audioop.lin2alaw(pcm.tobytes(), 2))
        allbytes = bytes(range(256))
        self.assertTrue((cc.ulaw_decode(allbytes) == np.frombuffer(audioop.ulaw2lin(allbytes, 2), '<i2')).all())
        self.assertTrue((cc.alaw_decode(allbytes) == np.frombuffer(audioop.alaw2lin(allbytes, 2), '<i2')).all())

    def test_roundtrip_error_is_small(self):
        t = np.arange(8000) / 8000
        x = (12000 * np.sin(2 * np.pi * 440 * t)).astype(np.int16)
        for enc, dec in ((cc.ulaw_encode, cc.ulaw_decode), (cc.alaw_encode, cc.alaw_decode)):
            y = dec(enc(x)); snr = 10 * np.log10(np.sum(x.astype(float) ** 2) / np.sum((x - y).astype(float) ** 2))
            self.assertGreater(snr, 30)

    def test_to_model_audio(self):
        a = cc.to_model_audio(np.array([0, 16384, 32767], dtype=np.int16))
        self.assertEqual(a.dtype, np.float32); self.assertEqual(len(a), 6); self.assertLessEqual(float(np.abs(a).max()), 1.0)

    @staticmethod
    def rtp(seq, payload, pt=0, ts=0):
        import struct
        return struct.pack('!BBHII', 0x80, pt, seq, ts, 1234) + payload

    def test_rtp_parse_and_reorder_and_loss(self):
        frame = bytes([0xFF]) * 160
        r = cc.RtpReassembler(window=3)
        out = [r.push(self.rtp(10, frame)), r.push(self.rtp(12, frame)), r.push(self.rtp(11, frame))]
        self.assertEqual([len(o) for o in out], [160, 0, 320])
        r2 = cc.RtpReassembler(window=2)
        r2.push(self.rtp(1, frame))
        got = np.concatenate([r2.push(self.rtp(3, frame)), r2.push(self.rtp(4, frame))])
        self.assertEqual(r2.lost, 1); self.assertEqual(len(got), 480)

    def test_rtp_rejects_bad_input(self):
        with self.assertRaises(ValueError): cc.parse_rtp(b'short')
        with self.assertRaises(ValueError): cc.parse_rtp(b'\x40' + bytes(11))
        with self.assertRaises(ValueError): cc.RtpReassembler().push(self.rtp(1, b'x', pt=96))

    def test_twilio_stream(self):
        t = cc.TwilioStreamAdapter()
        t.feed(json.dumps({'event': 'connected'}))
        t.feed(json.dumps({'event': 'start', 'start': {'streamSid': 'S', 'callSid': 'C', 'mediaFormat': {'encoding': 'audio/x-mulaw', 'sampleRate': 8000, 'channels': 1}}}))
        payload = base64.b64encode(bytes([0xFF] * 160)).decode()
        t.feed(json.dumps({'event': 'media', 'media': {'payload': payload}})); t.feed(json.dumps({'event': 'stop'}))
        self.assertEqual(len(t.audio16k()), 320)

    def test_twilio_rejects_wrong_format_and_early_media(self):
        t = cc.TwilioStreamAdapter()
        with self.assertRaises(ValueError):
            t.feed(json.dumps({'event': 'media', 'media': {'payload': ''}}))
        with self.assertRaises(ValueError):
            t.feed(json.dumps({'event': 'start', 'start': {'mediaFormat': {'encoding': 'audio/x-alaw', 'sampleRate': 8000}}}))
        with self.assertRaises(ValueError):
            t.feed(json.dumps({'event': 'weird'}))
        with self.assertRaises(ValueError): cc.TwilioStreamAdapter().audio16k()


class Rails(unittest.TestCase):
    def test_upi_uri_roundtrip(self):
        uri = payment_rails.build_upi_uri('chandu@okbank', 'Chandu K', '5000.50', 'rent', 'TR1')
        q = payment_rails.parse_upi_uri(uri)
        self.assertEqual((q['pa'], q['pn'], q['am'], q['cu']), ('chandu@okbank', 'Chandu K', '5000.50', 'INR'))

    def test_invalid_inputs(self):
        for args in (('bad vpa', 'N', '1'), ('a@b', 'N', '0'), ('ab@bank', 'N', '1.234'), ('ab@bank', '', '1'), ('ab@bank', 'N', '9999999')):
            with self.assertRaises(ValueError): payment_rails.build_upi_uri(*args)
        with self.assertRaises(ValueError): payment_rails.parse_upi_uri('upi://pay?pa=ab@bank&pn=N&am=1&cu=USD')
        with self.assertRaises(ValueError): payment_rails.parse_upi_uri('upi://pay?pa=ab@bank&pn=N&am=1&cu=INR&evil=1')
        with self.assertRaises(ValueError): payment_rails.parse_upi_uri('https://x.test')

    def test_sandbox_rail_idempotent_reference(self):
        rail = payment_rails.SandboxRail(10000)
        uri = payment_rails.build_upi_uri('ab@bank', 'N', '60')
        self.assertEqual(rail.submit(uri, 'r1')['status'], 'success')
        self.assertEqual(rail.submit(uri, 'r1')['status'], 'duplicate')
        self.assertEqual(rail.submit(uri, 'r2')['status'], 'failed')

    def test_shadow_metrics(self):
        s = payment_rails.ShadowRail()
        s.observe('1', 'allow', 'allow'); s.observe('2', 'deny', 'allow'); s.observe('3', 'allow', 'deny'); s.observe('4', 'step_up', 'step_up')
        m = s.metrics()
        self.assertEqual((m['n'], m['agreement']), (4, 0.5))
        self.assertEqual((m['voice_would_block_legacy_allowed'], m['voice_would_allow_legacy_blocked']), (1, 1))
        with self.assertRaises(ValueError): s.observe('5', 'maybe', 'allow')


class WebhookTests(unittest.TestCase):
    def test_sign_verify_and_tamper(self):
        body = '{"a":1}'; h = api.sign_webhook('s' * 20, 1000, body)
        self.assertTrue(api.verify_webhook('s' * 20, h, body, now=1100))
        self.assertFalse(api.verify_webhook('s' * 20, h, body + ' ', now=1100))
        self.assertFalse(api.verify_webhook('t' * 20, h, body, now=1100))
        self.assertFalse(api.verify_webhook('s' * 20, h, body, now=5000))
        self.assertFalse(api.verify_webhook('s' * 20, 'garbage', body))

    def test_url_validation(self):
        for bad in ('http://example.com/x', 'https://127.0.0.1/x', 'https://10.0.0.5/x', 'https://169.254.169.254/x',
                    'https://user:pw@8.8.8.8/x', 'ftp://8.8.8.8/x', 'https://[::1]/x'):
            with self.assertRaises(ValueError): api.validate_webhook_url(bad)
        api.validate_webhook_url('https://8.8.8.8/hook')
        api.validate_webhook_url('http://127.0.0.1:9/hook', allow_local=True)

    def test_retry_failed_deliveries(self):
        calls = []; fail = [True]
        def sink(url, headers, body):
            if fail[0]: raise IOError('down')
            calls.append((url, headers, body))
        d = api.WebhookDispatcher(sink=sink, allow_local=True); d.register('http://127.0.0.1:9/h', 'x' * 16)
        d.emit('t', {}); self.assertEqual(len(d.failed), 1)
        fail[0] = False; self.assertEqual(d.retry_failed(), 1); self.assertEqual(len(calls), 1)
        self.assertTrue(api.verify_webhook('x' * 16, calls[0][1]['QuantaVoice-Signature'], calls[0][2]))
        with self.assertRaises(ValueError): d.register('http://127.0.0.1:9/h', 'short')


class ApiEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = BackendStore(Path(self.tmp.name) / 'l.db', demo=True, provider='hybrid')
        self.audit = AuditLog(Path(self.tmp.name) / 'a.jsonl')
        self.hooks = []
        self.disp = api.WebhookDispatcher(sink=lambda u, h, b: self.hooks.append((h, b)), allow_local=True)
        self.disp.register('http://127.0.0.1:9/hook', 'w' * 20)
        self.service = api.AuthorizationService(self.store, self.audit, challenges=challenge_phrase.ChallengeService(), dispatcher=self.disp)
        self.keys = api.ApiKeys(); self.key = self.keys.create('partner')
        self.server, _ = api.serve(self.service, self.keys, api.RateLimiter(per_second=1000, burst=1000))
        self.base = 'http://127.0.0.1:%d' % self.server.server_port
        self.client = sdk.Client(self.base, self.key, sleep=lambda s: None)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.store.close(); self.tmp.cleanup()

    def raw(self, method, path, body=None, headers=None):
        from urllib.request import Request, build_opener, ProxyHandler
        from urllib.error import HTTPError
        h = {'Content-Type': 'application/json'}; h.update(headers or {})
        try:
            with build_opener(ProxyHandler({})).open(Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)) as r:
                return r.status, json.loads(r.read()), r.headers
        except HTTPError as e:
            return e.code, json.loads(e.read()), e.headers

    def test_full_happy_path_with_step_up(self):
        a = self.client.create_authorization('Chandu', 'chandu@demo', '6000', context=dict(GOOD, new_payee=True, device_bound=False), customer_ref='c1')
        self.assertEqual(a['status'], 'pending_review'); self.assertTrue(a['step_up_required'])
        with self.assertRaises(sdk.QuantaVoiceError) as ctx:
            self.client.confirm_authorization(a['id'], a['digest'])
        self.assertEqual(ctx.exception.code, 'step_up_required')
        ch = self.client.issue_challenge(a['id'], 'es')
        self.assertFalse(self.client.verify_challenge(a['id'], ch['challenge_id'], 'uno dos tres')['verified'])
        ch = self.client.issue_challenge(a['id'], 'es')
        self.assertTrue(self.client.verify_challenge(a['id'], ch['challenge_id'], ch['spoken_form'])['verified'])
        with self.assertRaises(sdk.QuantaVoiceError) as ctx:  # still needs operator review
            self.client.confirm_authorization(a['id'], a['digest'])
        self.assertEqual(ctx.exception.code, 'confirm_failed')
        self.store.approve_from_console(a['id'])
        done = self.client.confirm_authorization(a['id'], a['digest'])
        self.assertEqual(done['status'], 'consumed')
        self.assertEqual(self.client.get_authorization(a['id'])['status'], 'consumed')
        with self.assertRaises(sdk.QuantaVoiceError): self.client.confirm_authorization(a['id'], a['digest'])
        self.assertEqual([json.loads(b)['type'] for _, b in self.hooks], ['authorization.created', 'authorization.confirmed'])
        for h, b in self.hooks: self.assertTrue(api.verify_webhook('w' * 20, h['QuantaVoice-Signature'], b))
        ok, n, msg = self.audit.verify(); self.assertTrue(ok, msg); self.assertGreaterEqual(n, 6)

    def test_idempotency(self):
        body = {'recipient': 'A', 'destination': 'a@demo', 'amount': '10', 'context': GOOD}
        s1, r1, _ = self.raw('POST', '/v1/authorizations', body, {'Authorization': 'Bearer ' + self.key, 'Idempotency-Key': 'key-12345678'})
        s2, r2, h2 = self.raw('POST', '/v1/authorizations', body, {'Authorization': 'Bearer ' + self.key, 'Idempotency-Key': 'key-12345678'})
        self.assertEqual((s1, s2, r1['id'] == r2['id'], h2['Idempotent-Replayed']), (201, 200, True, 'true'))
        s3, r3, _ = self.raw('POST', '/v1/authorizations', dict(body, amount='11'), {'Authorization': 'Bearer ' + self.key, 'Idempotency-Key': 'key-12345678'})
        self.assertEqual((s3, r3['error']['code']), (422, 'idempotency_conflict'))
        s4, r4, _ = self.raw('POST', '/v1/authorizations', body, {'Authorization': 'Bearer ' + self.key})
        self.assertEqual((s4, r4['error']['code']), (400, 'idempotency_key_required'))

    def test_spoof_is_declined_and_no_intent_created(self):
        a = self.client.create_authorization('A', 'a@demo', '10', context=dict(GOOD, cm_score=0.05, asv_score=0.1))
        self.assertEqual((a['status'], a['id']), ('declined', None))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM transactions').fetchone()[0], 0)
        self.assertEqual(json.loads(self.hooks[-1][1])['type'], 'authorization.declined')

    def test_authentication_scopes_and_isolation(self):
        self.assertEqual(self.raw('POST', '/v1/authorizations', {}, {'Idempotency-Key': 'key-12345678'})[0], 401)
        self.assertEqual(self.raw('GET', '/v1/authorizations/' + '0' * 32, headers={'Authorization': 'Bearer qvk_deadbeef.' + 'x' * 30})[0], 401)
        ro = self.keys.create('reader', scopes=('authorizations:read',))
        self.assertEqual(self.raw('POST', '/v1/authorizations', {}, {'Authorization': 'Bearer ' + ro, 'Idempotency-Key': 'key-12345678'})[0], 403)
        a = self.client.create_authorization('A', 'a@demo', '10', context=GOOD)
        other = sdk.Client(self.base, self.keys.create('other'))
        with self.assertRaises(sdk.QuantaVoiceError) as ctx: other.get_authorization(a['id'])
        self.assertEqual(ctx.exception.status, 404)
        key_id = self.key.split('.')[0][4:]; self.keys.revoke(key_id)
        with self.assertRaises(sdk.QuantaVoiceError) as ctx: self.client.get_authorization(a['id'])
        self.assertEqual(ctx.exception.status, 401)
        self.assertTrue(any(json.loads(l)['event'] == 'auth.failed' for l in self.audit.export_jsonl()))

    def test_validation_errors(self):
        for body in ({'recipient': 'A'}, {'recipient': 'A', 'destination': 'a@demo', 'amount': 'abc'},
                     {'recipient': 'A', 'destination': 'a@demo', 'amount': '10', 'extra': 1},
                     {'recipient': 'A', 'destination': 'a@demo', 'amount': '10', 'context': {'asv_score': 5}},
                     {'recipient': 'A', 'destination': 'a@demo', 'amount': '10', 'context': {'bogus': 1}},
                     {'recipient': 'A', 'destination': 'not-a-demo-address', 'amount': '10'},
                     {'recipient': 'A', 'destination': 'a@demo', 'amount': '999999'}):
            s, r, _ = self.raw('POST', '/v1/authorizations', body, {'Authorization': 'Bearer ' + self.key, 'Idempotency-Key': 'key-' + str(abs(hash(str(body))))[:10].ljust(8, '0')})
            self.assertEqual(s, 400, body)
        self.assertEqual(self.raw('POST', '/v1/authorizations', None, {'Authorization': 'Bearer ' + self.key, 'Content-Type': 'text/plain'})[0], 415)

    def test_rate_limit_and_sdk_retry(self):
        now = [0.0]; lim = api.RateLimiter(per_second=1, burst=2, clock=lambda: now[0])
        lim.check('k'); lim.check('k')
        with self.assertRaises(api.ApiError) as ctx: lim.check('k')
        self.assertEqual(ctx.exception.status, 429); now[0] = 2; lim.check('k')

    def test_health_openapi_and_origin_block(self):
        self.assertEqual(self.raw('GET', '/v1/health')[1]['status'], 'ok')
        spec = self.raw('GET', '/v1/openapi.json')[1]
        self.assertEqual(spec['openapi'], '3.0.3'); self.assertIn('/v1/authorizations/{id}/confirm', spec['paths'])
        self.assertEqual(self.raw('GET', '/v1/health', headers={'Origin': 'http://evil.test'})[0], 403)  # browser origins refused everywhere
        self.assertEqual(self.raw('GET', '/v1/authorizations/' + '0' * 32, headers={'Origin': 'http://evil.test', 'Authorization': 'Bearer ' + self.key})[0], 403)

    def test_refuses_non_loopback_bind(self):
        with self.assertRaises(ValueError): api.serve(self.service, self.keys, host='0.0.0.0')

    def test_concurrent_creates_use_separate_owners(self):
        k2 = self.keys.create('second'); c2 = sdk.Client(self.base, k2); out = []
        def go(c): out.append(c.create_authorization('A', 'a@demo', '10', context=GOOD)['id'])
        ts = [threading.Thread(target=go, args=(c,)) for c in (self.client, c2)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(len(set(out)), 2)
        pending = self.store.db.execute("SELECT COUNT(*) FROM transactions WHERE status='pending'").fetchone()[0]
        self.assertEqual(pending, 2)  # one active intent per partner key, neither cancelled the other


if __name__ == '__main__':
    unittest.main()
