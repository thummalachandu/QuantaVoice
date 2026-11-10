@echo off
setlocal
cd /d "%~dp0"
echo QuantaVoice v15 - separate SIMULATED backend lab
py -V:3.12 "%~dp0bootstrap_backend.py" --demo-review
if errorlevel 1 (
  echo Keep this error and report it. Python 3.12 is required.
  pause
)
