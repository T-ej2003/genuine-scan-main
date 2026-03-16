@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "INSTALL_SCRIPT=%~dp0install-startup-task.ps1"
set "CONNECTOR_EXE=%~dp0bin\mscqr-local-print-agent.exe"
set "DIALOG_TITLE=MSCQR Connector Setup"

if not exist "%INSTALL_SCRIPT%" (
  echo.
  echo MSCQR Connector setup cannot start from inside the ZIP preview.
  echo Extract the entire ZIP to a normal folder first, then run Install Connector.cmd again.
  echo.
  echo Missing file:
  echo   %INSTALL_SCRIPT%
  set "DIALOG_MESSAGE=MSCQR Connector setup could not start. Extract the ZIP to a normal folder first, then run Install Connector.cmd again."
  set "DIALOG_ICON=Error"
  call :show_dialog
  pause
  exit /b 1
)

if not exist "%CONNECTOR_EXE%" (
  echo.
  echo MSCQR Connector package is incomplete or was not fully extracted.
  echo Extract the entire ZIP to a normal folder first, then run Install Connector.cmd again.
  set "DIALOG_MESSAGE=MSCQR Connector setup could not start because the package is incomplete. Extract the ZIP to a normal folder first, then run Install Connector.cmd again."
  set "DIALOG_ICON=Error"
  call :show_dialog
  pause
  exit /b 1
)

set "MSCQR_PACKAGED_INSTALL=1"
set "MSCQR_WEB_APP_BASE_URL=__MSCQR_WEB_APP_BASE_URL__"
set "MSCQR_CONNECTOR_VERSION=__MSCQR_CONNECTOR_VERSION__"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%INSTALL_SCRIPT%"
set "EXITCODE=%ERRORLEVEL%"

if "%EXITCODE%"=="10" (
  echo.
  echo MSCQR Connector installed, but printer readiness still needs attention.
  exit /b 10
)

if not "%EXITCODE%"=="0" (
  echo.
  echo MSCQR Connector setup did not complete.
  exit /b %EXITCODE%
)

echo.
echo MSCQR Connector setup is complete.
exit /b 0

:show_dialog
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show($env:DIALOG_MESSAGE, $env:DIALOG_TITLE, [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::%DIALOG_ICON%) | Out-Null" >nul 2>&1
exit /b 0
