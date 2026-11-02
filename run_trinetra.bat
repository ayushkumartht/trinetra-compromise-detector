@echo off
REM TRINETRA dashboard (Slips extension) - Windows launcher
cd /d "%~dp0"
python -m pip install --quiet -r compromise_dashboard\requirements.txt
start "" http://127.0.0.1:5050
python -m compromise_dashboard %*
