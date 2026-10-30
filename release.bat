@echo off
rem New release: commit with the text of COMMIT_MSG.txt and tag = VERSION of sniffer.py (e.g. v0.3.0)
rem Before: change VERSION in sniffer.py, CHANGELOG.md and COMMIT_MSG.txt
cd /d "%~dp0"
for /f "delims=" %%n in ('python exe_name.py') do set NAME=%%n
set TAG=%NAME:IEC61850ANALYZER =%
echo Release %TAG%
git add -A
git commit -F COMMIT_MSG.txt
git push
git tag -a %TAG% -F COMMIT_MSG.txt
git push origin %TAG%
echo.
echo GitHub builds %NAME%.exe: https://github.com/IevgenGerman/IEC61850ANALYZER/actions
pause
