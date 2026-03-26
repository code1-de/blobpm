@echo off
cd /d "%~dp0"
cargo build --release
if errorlevel 1 exit /b 1
copy /y target\release\blob-shim.exe bin\shim-cli.exe
echo Built shim-cli.exe (%~dp0bin\shim-cli.exe)
