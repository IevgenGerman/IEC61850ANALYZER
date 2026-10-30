@echo off
rem Builds the folder "dist\IEC61850ANALYZER <version>\" with the exe (--onedir: fewer antivirus false
rem positives than one self-extracting exe) and "dist\IEC61850ANALYZER <version>.zip" to pass on
cd /d "%~dp0"
python -m pip install --upgrade pip
pip install -r requirements.txt pyinstaller
for /f "delims=" %%n in ('python exe_name.py') do set EXENAME=%%n
echo Building %EXENAME%.exe ...
pyinstaller --clean --onedir --noupx --windowed --name "%EXENAME%" --hidden-import scapy.all --collect-submodules scapy sniffer.py
echo.
powershell -NoProfile -Command "Compress-Archive -Path 'dist\%EXENAME%' -DestinationPath 'dist\%EXENAME%.zip' -Force"
echo Result: "dist\%EXENAME%\%EXENAME%.exe"  and  "dist\%EXENAME%.zip"
pause
