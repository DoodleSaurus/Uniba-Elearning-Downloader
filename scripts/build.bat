@echo off
REM Build script for UniBA E-Learning Downloader (supports PyInstaller and Nuitka)

setlocal enabledelayedexpansion

REM Change to repository root
pushd "%~dp0\.." || (echo Failed to change directory. Exiting.& exit /b 1)

REM Allow override: set PYTHON_EXEC to full path before running, or pass builder as first arg (pyi|nuitka)
set "REQUESTED_BUILDER=%~1"
if "%REQUESTED_BUILDER%"=="" set "REQUESTED_BUILDER=pyi"

REM Detect Python command. Priority:
REM 1) environment variable PYTHON_EXEC (full path)
REM 2) py -3
REM 3) python
REM 4) python3
set "PY_CMD="
set "PY_ARGS="

if defined PYTHON_EXEC (
  "%PYTHON_EXEC%" -c "import sys" >NUL 2>&1
  if not errorlevel 1 (
    set "PY_CMD=%PYTHON_EXEC%"
    set "PY_ARGS="
  )
)

if not defined PY_CMD (
  py -3 -c "import sys" >NUL 2>&1 && (set "PY_CMD=py" & set "PY_ARGS=-3")
)
if not defined PY_CMD (
  python -c "import sys" >NUL 2>&1 && (set "PY_CMD=python" & set "PY_ARGS=")
)
if not defined PY_CMD (
  python3 -c "import sys" >NUL 2>&1 && (set "PY_CMD=python3" & set "PY_ARGS=")
)

if not defined PY_CMD (
  echo Python not found. Install Python or set PYTHON_EXEC to full python.exe path.
  echo Example: set PYTHON_EXEC=C:\Python39\python.exe
  pause
  popd
  endlocal
  exit /b 1
)

echo Using Python command: "%PY_CMD%" %PY_ARGS%

REM Choose builder
set "BUILDER=%REQUESTED_BUILDER%"
if /I "%BUILDER%"=="pyi" set "BUILDER=pyi"
if /I "%BUILDER%"=="nuitka" set "BUILDER=nuitka"

REM Icon argument
set "ICON_PATH=icon.ico"
if not exist "%ICON_PATH%" (
  echo Icon not found at "%ICON_PATH%". Building without icon.
  set "ICON_ARG="
) else (
  set "ICON_ARG=--icon="%ICON_PATH%""
)

REM Helper to run python module: will expand correctly for quoted paths
set "PYRUN=""%PY_CMD%"" %PY_ARGS% -m"

REM Build with PyInstaller (default)
if /I "%BUILDER%"=="pyi" (
  echo Checking PyInstaller...
  "%PY_CMD%" %PY_ARGS% -m PyInstaller --version >NUL 2>&1
  if errorlevel 1 (
    echo PyInstaller not found. Installing...
    "%PY_CMD%" %PY_ARGS% -m pip install --user pyinstaller || (
      echo Failed to install PyInstaller. Install manually and re-run.
      pause
      popd
      endlocal
      exit /b 1
    )
  )

  echo Running PyInstaller...
  "%PY_CMD%" %PY_ARGS% -m PyInstaller --noconfirm --onefile --windowed %ICON_ARG% "src\UnibaElearningDownloader.py"
  if errorlevel 1 (
    echo PyInstaller build failed. See output above.
    pause
    popd
    endlocal
    exit /b 1
  )
  echo PyInstaller build succeeded. Check the dist\ folder.
  REM locate and report exe
  call :locate_exe
  pause
  popd
  endlocal
  exit /b 0
)

REM Build with Nuitka
if /I "%BUILDER%"=="nuitka" (
  echo Checking Nuitka...
  "%PY_CMD%" %PY_ARGS% -m nuitka --version >NUL 2>&1
  if errorlevel 1 (
    echo Nuitka not found. Installing...
    "%PY_CMD%" %PY_ARGS% -m pip install --user nuitka || (
      echo Failed to install Nuitka. Install manually and re-run.
      pause
      popd
      endlocal
      exit /b 1
    )
  )

  echo Running Nuitka (standalone)...
  "%PY_CMD%" %PY_ARGS% -m nuitka --standalone --windows-disable-console --output-dir=dist "src\UnibaElearningDownloader.py"
  if errorlevel 1 (
    echo Nuitka build failed. See output above.
    pause
    popd
    endlocal
    exit /b 1
  )
  echo Nuitka build succeeded. Check the dist\ folder.
  REM locate and report exe
  call :locate_exe
  pause
  popd
  endlocal
  exit /b 0
)

echo Unknown builder: %BUILDER%. Supported: pyi, nuitka
popd
endlocal
exit /b 1

:locate_exe
REM Try to find an .exe in dist or its subfolders and report the first match
set "FOUND="
for %%F in ("dist\*.exe") do if not defined FOUND set "FOUND=%%~fF"
if not defined FOUND (
  for /R "dist" %%F in (*.exe) do if not defined FOUND set "FOUND=%%~fF"
)
if defined FOUND (
  echo Executable located at: "%FOUND%"
) else (
  echo No executable found in dist. Listing dist contents:
  if exist dist (
    dir /b /s dist
  ) else (
    echo dist folder not found.
  )
)
goto :eof