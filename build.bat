@echo off

setlocal EnableExtensions
pushd "%~dp0"

set "APP=mft-evilhunter"
set "ENTRY=mft-evilhunter.py"
set "PKG=mft_evilhunter"
set "ICON=%PKG%\gui\assets\icon.ico"
set "ASSETS=%PKG%\gui\assets"
set "RULES=%PKG%\rules\default.json"
set "VENV=build-venv"
set "DIST=dist"
set "WORK=build"
set "PYVER=3.12"
set "PYFULL=3.12.10"

echo ===========================
echo   Building MFT-EvilHunter
echo ===========================

if not exist "%ENTRY%"          ( echo [ERROR] %ENTRY% not found.          & goto :fail )
if not exist "%PKG%\"           ( echo [ERROR] %PKG%\ package not found.   & goto :fail )
if not exist "%ICON%"           ( echo [ERROR] %ICON% not found.           & goto :fail )
if not exist "%RULES%"          ( echo [ERROR] %RULES% not found.          & goto :fail )
if not exist "requirements.txt" ( echo [ERROR] requirements.txt not found. & goto :fail )

call :ensure_python || goto :fail

if exist "%VENV%\Scripts\python.exe" (
    "%VENV%\Scripts\python.exe" -c "import sys;raise SystemExit(0 if sys.version_info[:2]==(3,12) else 1)" 2>nul || (
        echo [*] Existing venv is not Python %PYVER% - recreating...
        rmdir /s /q "%VENV%"
    )
)

if not exist "%VENV%\Scripts\python.exe" (
    echo [*] Creating virtual environment: %VENV%
    %PY% -m venv "%VENV%" || goto :fail
)

set "PYEXE=%VENV%\Scripts\python.exe"
echo [*] Installing Python dependencies...
"%PYEXE%" -m pip install --upgrade pip wheel >nul
"%PYEXE%" -m pip install -r requirements.txt pyinstaller || goto :fail

for %%D in ("%DIST%" "%WORK%") do if exist "%%~D" rmdir /s /q "%%~D"

echo [*] Building %APP%.exe (this takes a few minutes)...
"%PYEXE%" -m PyInstaller ^
    --onefile --windowed --clean --noconfirm --name "%APP%" ^
    --distpath "%DIST%" --workpath "%WORK%" --specpath "%WORK%" ^
    --icon "%~dp0%ICON%" ^
    --collect-submodules %PKG% ^
    --add-data "%~dp0%RULES%;%PKG%\rules" ^
    --add-data "%~dp0%ASSETS%;%ASSETS%" ^
    --exclude-module tkinter ^
    --exclude-module matplotlib ^
    --exclude-module numpy ^
    --exclude-module PIL ^
    --exclude-module pytest ^
    "%ENTRY%" || goto :fail

if not exist "%DIST%\%APP%.exe" ( echo [ERROR] Missing %DIST%\%APP%.exe & goto :fail )

for %%D in ("%WORK%" "%VENV%") do rmdir /s /q "%%~D" 2>nul
del /q python-installer.exe >nul 2>&1

echo.
echo [DONE] Single binary built:
dir /b "%DIST%"
echo.
pause
popd
endlocal
exit /b 0


:ensure_python
set "PYEXE_SYS=%LocalAppData%\Programs\Python\Python%PYVER:.=%\python.exe"
set "PYEXE_ALL=%ProgramFiles%\Python%PYVER:.=%\python.exe"
set "PY="
if exist "%PYEXE_SYS%" set PY="%PYEXE_SYS%"
if not defined PY if exist "%PYEXE_ALL%" set PY="%PYEXE_ALL%"
if not defined PY (
    py -%PYVER% --version >nul 2>&1 && set "PY=py -%PYVER%"
)
if defined PY goto :py_verify

echo [*] Python %PYVER% not found - downloading the official installer (%PYFULL%)...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri https://www.python.org/ftp/python/%PYFULL%/python-%PYFULL%-amd64.exe -OutFile python-installer.exe; Start-Process -FilePath python-installer.exe -ArgumentList '/quiet','InstallAllUsers=0','InstallLauncherAllUsers=0','PrependPath=1','Include_test=0' -Wait" || (echo [ERROR] Python download/install failed. & exit /b 1)

if exist "%PYEXE_SYS%" set PY="%PYEXE_SYS%"
if not defined PY (
    echo [ERROR] Python %PYVER% installed but not found at:
    echo         "%PYEXE_SYS%"
    echo         Open a NEW terminal and run build.bat again.
    exit /b 1
)

:py_verify
set "PYVEROUT="
for /f "tokens=1,2" %%a in ('%PY% --version 2^>^&1') do set "PYVEROUT=%%a %%b"
echo %PYVEROUT% | findstr /b /c:"Python %PYVER%" >nul || (
    echo [ERROR] Detected Python is not %PYVER% ^(got "%PYVEROUT%"^).
    exit /b 1
)
echo [*] Using %PYVEROUT%
exit /b 0

:fail
echo.
echo [BUILD FAILED] See the messages above.
echo.
pause
popd
endlocal
exit /b 1
