@echo off
setlocal
cd /d "%~dp0"
echo QuantaVoice v17.3 - LIVE SECURITY DEMO (simulated funds, loopback only)
py -V:3.12 "%~dp0bootstrap_backend.py" --live-demo
if errorlevel 1 (
  echo Keep this error and report it. Python 3.12 is required.
  pause
)
