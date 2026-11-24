@echo off
setlocal EnableExtensions
set "UNINSTALLER=%~dp0unins000.exe"
if not exist "%UNINSTALLER%" (
  echo MSCQR Connector's Windows uninstaller is missing. No files were removed.
  exit /b 1
)
"%UNINSTALLER%" %*
exit /b %ERRORLEVEL%
