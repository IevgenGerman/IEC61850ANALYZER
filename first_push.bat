@echo off
rem First upload to GitHub with the commit text from COMMIT_MSG.txt and the release tag
cd /d "%~dp0"
git init
git add -A
git commit -F COMMIT_MSG.txt
git branch -M main
git remote add origin https://github.com/IevgenGerman/IEC61850ANALYZER.git
git push -u origin main
git tag -a v0.2.0 -F COMMIT_MSG.txt
git push origin v0.2.0
pause
