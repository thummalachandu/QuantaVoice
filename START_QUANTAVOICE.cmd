@echo off
setlocal
cd /d "%~dp0"
echo QuantaVoice v15 Security Backend Update - original voice demo
py -V:3.12 -c "import sys; assert sys.version_info[:2] == (3,12)" >nul 2>&1
if not errorlevel 1 (
  py -V:3.12 "%~dp0bootstrap.py" %*
  goto finished
)
py -3.12 -c "import sys; assert sys.version_info[:2] == (3,12)" >nul 2>&1
if not errorlevel 1 (
  py -3.12 "%~dp0bootstrap.py" %*
  goto finished
)
python -c "import sys; assert sys.version_info[:2] == (3,12)" >nul 2>&1
if not errorlevel 1 (
  python "%~dp0bootstrap.py" %*
  goto finished
)
echo Python 3.12 was not found. Install Python 3.12, then run this file again.
pause
exit /b 1
:finished
set "qv_exit=%errorlevel%"
if not "%qv_exit%"=="0" (
  echo.
  echo QuantaVoice stopped with an error. Copy the error shown above.
  pause
)
exit /b %qv_exit%
