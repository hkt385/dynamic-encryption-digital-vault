@echo off
setlocal
cd /d "%~dp0"

rem --- Read version from dedv\version.py ---
for /f "delims=" %%v in ('python -c "import sys; sys.path.insert(0,'dedv'); from version import __version__ as v; print(v)"') do set APP_VERSION=%%v
if "%APP_VERSION%"=="" (
    echo Could not read version from dedv\version.py
    exit /b 1
)
echo === Building DEDV %APP_VERSION% ===

rem --- Clean previous artifacts ---
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist installer rmdir /s /q installer

rem --- PyInstaller ---
python -m PyInstaller --noconfirm --clean DEDV.spec
if errorlevel 1 (
    echo PyInstaller build FAILED.
    exit /b 1
)
echo Application built: dist\DEDV\DEDV.exe

rem --- Inno Setup (optional: skipped with a notice if not installed) ---
set ISCC=
where ISCC >nul 2>nul && set ISCC=ISCC
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 7\ISCC.exe" set ISCC="%ProgramFiles%\Inno Setup 7\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 7\ISCC.exe" set ISCC="%ProgramFiles(x86)%\Inno Setup 7\ISCC.exe"
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 7\ISCC.exe" set ISCC="%LOCALAPPDATA%\Programs\Inno Setup 7\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set ISCC="%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set ISCC="%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not defined ISCC (
    echo.
    echo Inno Setup not found - installer NOT created. Install it from https://jrsoftware.org/isdl.php
    echo and run build.bat again. The application itself is ready in dist\DEDV\.
    exit /b 2
)

%ISCC% /DAppVersion=%APP_VERSION% DEDV.iss
if errorlevel 1 (
    echo Inno Setup FAILED.
    exit /b 1
)
echo.
echo === Done: installer\DEDV_Setup.exe (version %APP_VERSION%) ===
endlocal
