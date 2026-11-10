"""Windows first-run setup; subsequent launches reuse the local environment."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
ENV = ROOT / '.venv'
PYTHON = ENV / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')

def run(args):
    subprocess.run([str(x) for x in args], cwd=ROOT, check=True)

def main():
    if sys.version_info[:2] != (3,12):
        raise RuntimeError('Python 3.12 is required.')
    if not PYTHON.exists():
        print('Creating the private Python environment…', flush=True)
        run([sys.executable, '-m', 'venv', ENV])
    requirement = ROOT/'requirements.txt'
    digest = hashlib.sha256(requirement.read_bytes()).hexdigest()
    marker = ENV/'quantavoice-requirements.sha256'
    if not marker.exists() or marker.read_text() != digest:
        print('Installing dependencies. Keep this window open; internet is required.', flush=True)
        run([PYTHON, '-m', 'pip', 'install', '-r', requirement])
        marker.write_text(digest)
    if not (ROOT/'quantavoice/models/faster-whisper-small/setup-complete.txt').exists():
        run([PYTHON, ROOT/'run.py', '--setup-whisper'])
    run([PYTHON, ROOT/'run.py', *sys.argv[1:]])

if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print(f'Setup or launch failed: {exc}', file=sys.stderr)
        sys.exit(1)
