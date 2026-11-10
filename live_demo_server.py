"""v17.3 live security demo: the 7-layer web page driven by the real seven_flow engine.

SIMULATED funds and simulated identity gates (voice, face, fingerprint, agent, video KYC). The PIN check, the
one-time code and the post-quantum payment envelope are real code. Loopback only; nothing here is production.
"""
import argparse
import ipaddress
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from seven_flow import Flow, NAMES

PAGE = Path(__file__).resolve().parent / 'web' / 'QuantaVoice_Live_Security_Demo.html'
MAX_BODY = 1024
RECIPIENT, AMOUNT, PIN = 'Tech Startup Fund', '5000', '246810'
REAL_LAYERS = (1, 2)   # 0-based: PIN (scrypt) and OTP are real checks; the other five gates are simulated
LOOPBACK = ('127.0.0.1', 'localhost', '::1')

SCENARIOS = {
    'legitimate': ('Legitimate TX', 'Normal transaction from the enrolled customer.', None, ''),
    'deepfake': ('Deepfake Attack', 'Attacker plays synthetic (text-to-speech) audio.', 0,
                 'Simulated: anti-spoofing rejected the audio as synthetic.'),
    'cloning': ('Voice Clone', 'Attacker uses a cloned voice trained on recordings.', 0,
                'Simulated: speaker and anti-spoofing evidence rejected.'),
    'hijack': ('Session Hijack', 'Attacker holds the session but cannot pass the fingerprint gate.', 4,
               'Simulated: fingerprint / FIDO2 gate rejected.'),
    'wrong_pin': ('Wrong PIN x3', 'Attacker guesses the PIN: real scrypt check and real lockout.', 1, ''),
}


def meta():
    return {'layers': [{'id': i + 1, 'name': n, 'kind': 'REAL' if i in REAL_LAYERS else 'SIMULATED'} for i, n in enumerate(NAMES)],
            'scenarios': [{'id': k, 'label': v[0], 'story': v[1]} for k, v in SCENARIOS.items()],
            'recipient': RECIPIENT, 'amount': AMOUNT}


def run_scenario(name):
    """Run one fresh Flow end to end and return every layer result. Raises ValueError for an unknown name."""
    if name not in SCENARIOS: raise ValueError('Unknown scenario.')
    _, story, fail_at, reason = SCENARIOS[name]
    f = Flow(); f.start(RECIPIENT, AMOUNT)
    layers = meta()['layers']
    for layer in layers: layer.update(status='NOT REACHED', detail='An earlier layer blocked the payment.')
    blocked_at = None
    for i in range(len(NAMES)):
        try:
            if i == 1:
                if fail_at == 1:
                    for _ in range(3):
                        try: f.verify_pin('000000')
                        except ValueError as exc: last = str(exc)
                    raise ValueError(last)
                f.verify_pin(PIN); detail = 'PIN verified (scrypt).'
            elif i == 2:
                f.verify_otp(f.issue_otp()); detail = 'One-time code issued and verified.'
            else:
                f.scenario(i, fail_at != i); detail = 'Simulated pass: no model or hardware was run.'
            layers[i].update(status='PASSED', detail=detail)
        except ValueError as exc:
            layers[i].update(status='REJECTED', detail=reason or str(exc)); blocked_at = i + 1
            break
    payment = {'status': 'blocked', 'balance_before': f.lab.balance / 100, 'balance_after': f.lab.balance / 100}
    if blocked_at is None:
        before = f.lab.balance / 100
        elapsed = f.encrypt(); f.confirm()
        payment = {'status': 'approved', 'suite': 'ML-KEM-768 + AES-256-GCM + ML-DSA-65',
                   'encrypt_ms': round(elapsed, 1), 'balance_before': before, 'balance_after': f.lab.balance / 100}
    return {'scenario': name, 'story': story, 'layers': layers, 'verdict': 'approved' if blocked_at is None else 'blocked',
            'blocked_at': blocked_at, 'payment': payment, 'simulated': True}


class Handler(BaseHTTPRequestHandler):
    server_version = 'QuantaVoiceLiveDemo'

    def log_message(self, *args): pass

    def _send(self, code, body, ctype='application/json'):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        for k, v in (('Content-Type', ctype + '; charset=utf-8'), ('Content-Length', str(len(data))), ('Cache-Control', 'no-store'),
                     ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'),
                     ('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                                                 "connect-src 'self'; base-uri 'none'; form-action 'none'")):
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def _same_origin(self):
        host = self.headers.get('Host', '')
        if urlparse('//' + host).hostname not in LOOPBACK: return False        # blocks DNS rebinding
        origin = self.headers.get('Origin')
        return origin is None or urlparse(origin).netloc == host                # blocks cross-site posts

    def do_GET(self):
        if not self._same_origin(): return self._send(403, {'error': 'forbidden'})
        if self.path == '/': return self._send(200, PAGE.read_bytes(), 'text/html')
        if self.path == '/api/meta': return self._send(200, meta())
        self._send(404, {'error': 'not found'})

    def do_POST(self):
        if not self._same_origin(): return self._send(403, {'error': 'forbidden'})
        if self.path != '/api/run': return self._send(404, {'error': 'not found'})
        try: size = int(self.headers.get('Content-Length', ''))
        except ValueError: return self._send(411, {'error': 'Content-Length required'})
        if size < 0 or size > MAX_BODY: return self._send(413, {'error': 'body too large'})
        try:
            name = json.loads(self.rfile.read(size) or b'{}').get('scenario')
            if not isinstance(name, str): raise ValueError('scenario must be a string')
            self._send(200, run_scenario(name))
        except (ValueError, AttributeError) as exc:
            self._send(400, {'error': str(exc)})


def serve(host='127.0.0.1', port=0):
    """Start the demo server in a thread. Loopback addresses only."""
    if not ipaddress.ip_address(host).is_loopback: raise ValueError('The live demo only binds to loopback.')
    server = ThreadingHTTPServer((host, port), Handler); server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    p = argparse.ArgumentParser(description='QuantaVoice live security demo (simulated, loopback only).')
    p.add_argument('--port', type=int, default=8790); p.add_argument('--no-browser', action='store_true')
    args = p.parse_args()
    server = serve(port=args.port); url = 'http://127.0.0.1:%d/' % server.server_port
    print('QuantaVoice live demo (SIMULATED funds and gates, loopback only): %s\nPress Ctrl+C to stop.' % url, flush=True)
    if not args.no_browser: webbrowser.open(url)
    try: threading.Event().wait()
    except KeyboardInterrupt: server.shutdown()


if __name__ == '__main__':
    main()
