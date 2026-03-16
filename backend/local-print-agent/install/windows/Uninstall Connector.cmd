@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "UNINSTALL_SCRIPT=%~dp0uninstall-startup-task.ps1"
if not exist "%UNINSTALL_SCRIPT%" (
  echo.
  echo MSCQR Connector removal script was not found in this folder.
  echo Extract the entire ZIP to a normal folder first, then run Uninstall Connector.cmd again.
  pause
  exit /b 1
)

set "MSCQR_PACKAGED_INSTALL=1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%UNINSTALL_SCRIPT%"
set "EXITCODE=%ERRORLEVEL%"

if not "%EXITCODE%"=="0" (
  echo.
  echo MSCQR Connector removal did not complete.
  pause
  exit /b %EXITCODE%
)

echo.
echo MSCQR Connector has been removed.
pause
exit /b 0
