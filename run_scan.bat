@echo off
cd /d "%~dp0"
python wifiscanner.py %*
if errorlevel 9009 echo Python is not installed. Get it from https://www.python.org/downloads/ (tick "Add to PATH").
pause
