@echo off
REM ==============================================================================
REM Wazuh Active Response Wrapper para Windows
REM Destino: C:\Program Files (x86)\ossec-agent\active-response\bin\yara_entropy_scan.cmd
REM ==============================================================================
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "%~dp0yara_entropy_scan.ps1"
