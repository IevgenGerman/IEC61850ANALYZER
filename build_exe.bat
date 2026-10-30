@echo off
rem Builds "dist\IEC61850ANALYZER <version>.exe" (version from sniffer.py)
cd /d "%~dp0"
python -m pip install --upgrade pip
pip install -r requirements.txt pyinstaller
for /f "delims=" %%n in ('python exe_name.py') do set EXENAME=%%n
echo Building %EXENAME%.exe ...
pyinstaller --clean --onefile --noupx --windowed --name "%EXENAME%" --hidden-import scapy.all --collect-submodules scapy sniffer.py
echo.
echo Result: "dist\%EXENAME%.exe"
pause
