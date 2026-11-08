@echo off
cd /d "%~dp0"
powershell -NoProfile -Command "Start-Process -FilePath python -ArgumentList 'main.py' -WorkingDirectory '%~dp0' -Verb RunAs"
