@echo off
setlocal
cd /d "%~dp0"
echo QuantaVoice v16 - SIMULATED REST API lab (loopback only)
py -V:3.12 "%~dp0bootstrap_backend.py" --api --demo-review
if errorlevel 1 (
  echo Keep this error and report it. Python 3.12 is required.
  pause
)
