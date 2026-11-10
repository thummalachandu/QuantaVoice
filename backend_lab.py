"""Optional loopback client/server lab. Never exposes banking or real approval."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'quantavoice'))
from backend_store import BackendStore


def handler_for(store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log Authorization headers or capabilities.

        def reply(self, status, payload):
            raw = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            self.connection.settimeout(5)
            try:
                # No CORS, browser origins, remote binding or host aliases.
                if self.headers.get('Origin') is not None:
                    raise PermissionError('Browser-origin requests are disabled in this desktop lab.')
                if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
                    raise PermissionError('Invalid host.')
                if self.headers.get('Content-Type') != 'application/json':
                    raise ValueError('JSON content type required.')
                if self.headers.get('Transfer-Encoding'):
                    raise ValueError('Chunked requests are not supported.')
                length = int(self.headers.get('Content-Length', '-1'))
                if not 0 <= length <= 16384:
                    raise ValueError('Request must be at most 16 KB.')
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer '):
                    raise PermissionError('Missing capability.')
                token = auth[7:]
                body = json.loads(self.rfile.read(length))
                if self.path == '/session':
                    if body != {}:
                        raise ValueError('Session request must be empty.')
                    result = store.session(token)
                elif self.path == '/status':
                    if body != {}:
                        raise ValueError('Status request must be empty.')
                    result = store.status(token)
                elif self.path == '/prepare':
                    result = store.prepare(token, body)
                elif self.path == '/confirm':
                    result = store.confirm(token, body)
                else:
                    self.reply(404, {'error': 'No such endpoint. Client approval is not available.'})
                    return
                self.reply(200, result)
            except PermissionError as exc:
                self.reply(403, {'error': str(exc)})
            except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
                self.reply(400, {'error': str(exc)})
            except Exception:
                self.reply(400, {'error': 'Request or cryptographic verification failed. No payment authorized.'})
    return Handler


def main():
    parser = argparse.ArgumentParser(description='Local research backend, no real money or biometric verification.')
    parser.add_argument('--demo-review', action='store_true', help='Allow explicitly simulated approval in this console')
    parser.add_argument('--provider', choices=['local', 'hybrid', 'qnu'], default='local')
    parser.add_argument('--client', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.client:
        from backend_client import main as client_main
        client_main(json.loads(sys.stdin.readline()))
        return
    store = BackendStore(ROOT / 'QuantaVoice_Data' / 'backend_lab.sqlite3',
                         demo=args.demo_review, provider=args.provider)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(store))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    child = None
    try:
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--client'],
                                 stdin=subprocess.PIPE, text=True, cwd=ROOT)
        child.stdin.write(json.dumps({'port': server.server_port, 'bootstrap': store.bootstrap_token,
                                     'fingerprint': store.crypto.fingerprint}) + '\n')
        child.stdin.close()
        print('QUANTAVOICE v15 BACKEND LAB: SIMULATED FUNDS ONLY', flush=True)
        print('Client window: enter exact details, then Submit for review.', flush=True)
        print('Console commands: list, approve TRANSACTION_ID, rotate, quit', flush=True)
        print('After submission, type list here. Approval only works with --demo-review.', flush=True)
        print('This is loopback HTTP. Do not expose it remotely. QNu is not connected.', flush=True)
        while True:
            try:
                command = input('Operator> ').strip().split()
            except (EOFError, KeyboardInterrupt):
                break
            if not command:
                continue
            try:
                if command == ['quit']:
                    break
                elif command == ['list']:
                    for intent in store.pending():
                        print(json.dumps(intent, ensure_ascii=False, indent=2))
                    print('Pending list complete. Times use Unix seconds.')
                elif len(command) == 2 and command[0] == 'approve':
                    matches = [x for x in store.pending() if x['id'] == command[1]]
                    if not matches:
                        raise ValueError('Unknown or expired pending ID.')
                    print(json.dumps(matches[0], ensure_ascii=False, indent=2))
                    if input('Type APPROVE for a simulated operator review: ').strip() != 'APPROVE':
                        print('No approval.'); continue
                    store.approve_from_console(command[1])
                    print('SIMULATED review approved. Now use Confirm in the client.')
                elif command == ['rotate']:
                    store.rotate()
                    print('Keys and client sessions rotated. Balance and consumed receipts preserved. Restart this lab to reconnect the client.')
                else:
                    print('Use list, approve TRANSACTION_ID, rotate or quit.')
            except Exception as exc:
                print('Blocked:', str(exc))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if child is not None and child.poll() is None:
            child.terminate()
            child.wait(timeout=5)
        store.close()


if __name__ == '__main__':
    main()
