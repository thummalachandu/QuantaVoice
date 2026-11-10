"""Separate lightweight setup. No speech models or paid API access required."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
ENV = ROOT / '.venv-backend'
PYTHON = ENV / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')

def main():
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError('Use Python 3.12.')
    if not PYTHON.exists():
        subprocess.run([sys.executable, '-m', 'venv', str(ENV)], cwd=ROOT, check=True)
    requirements = ROOT / 'requirements-backend.txt'
    digest = hashlib.sha256(requirements.read_bytes()).hexdigest()
    marker = ENV / 'requirements.sha256'
    if not marker.exists() or marker.read_text() != digest:
        subprocess.run([str(PYTHON), '-m', 'pip', 'install', '-r', str(requirements)], cwd=ROOT, check=True)
        marker.write_text(digest)
    args = [a for a in sys.argv[1:] if a not in ('--api', '--live-demo')]
    script = 'live_demo_lab.py' if '--live-demo' in sys.argv[1:] else ('api_lab.py' if '--api' in sys.argv[1:] else 'backend_lab.py')
    subprocess.run([str(PYTHON), str(ROOT / script), *args], cwd=ROOT, check=True)

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('Backend lab failed:', str(exc), file=sys.stderr)
        sys.exit(1)
