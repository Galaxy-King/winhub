@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "SOURCE=\\DC_FQDN\NETLOGON\WinHUBAgentDeploy"
set "LOGDIR=%ProgramData%\WinHUB\gpo-install"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" 2>nul

echo [%date% %time%] Starting WinHUB deployment wrapper>>"%LOGDIR%\startup-wrapper.log"

for /L %%i in (1,1,30) do (
    if exist "%SOURCE%\install-winhub-agent.ps1" if exist "%SOURCE%\deployment-manifest.json" goto runinstall
    echo [%date% %time%] Deployment source unavailable, attempt %%i/30>>"%LOGDIR%\startup-wrapper.log"
    %SystemRoot%\System32\timeout.exe /t 20 /nobreak >nul
)

echo [%date% %time%] ERROR: deployment source is unavailable: %SOURCE%>>"%LOGDIR%\startup-wrapper.log"
exit /b 2

:runinstall
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%SOURCE%\install-winhub-agent.ps1" -SourceDir "%SOURCE%" >>"%LOGDIR%\startup-wrapper.log" 2>&1
set "DEPLOY_EXIT=%ERRORLEVEL%"
echo [%date% %time%] Finished with exit code %DEPLOY_EXIT%>>"%LOGDIR%\startup-wrapper.log"
exit /b %DEPLOY_EXIT%
