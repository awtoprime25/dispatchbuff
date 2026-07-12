@echo off
rem Double-click launcher: shows the pairing QR, then starts the daemon.
rem Requires `dispatch init` to have run at least once (see README) — that
rem step only needs doing after a fresh machine/profile, not every restart.
setlocal
cd /d "%~dp0"

echo.
echo === DispatchFreeBuff ===
echo.

call npx dispatch pair --once
if errorlevel 1 (
  echo.
  echo Pairing step failed - see the error above.
  pause
  exit /b 1
)

start "" "%USERPROFILE%\.dispatch\pair-qr.html"

echo.
echo Starting freebuff... (this window is your live session — closing it stops freebuff)
echo.
call npx dispatch start

echo.
echo dispatch start exited.
pause
