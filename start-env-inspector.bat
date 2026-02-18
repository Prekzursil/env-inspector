@echo off
setlocal
set SCRIPT_DIR=%~dp0

where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "%SCRIPT_DIR%env_inspector.py" %*
  goto :eof
)

where python >nul 2>nul
if %errorlevel%==0 (
  python "%SCRIPT_DIR%env_inspector.py" %*
  goto :eof
)

if exist "%LocalAppData%\Programs\Python\Python312\python.exe" (
  "%LocalAppData%\Programs\Python\Python312\python.exe" "%SCRIPT_DIR%env_inspector.py" %*
  goto :eof
)

if exist "%LocalAppData%\Programs\Python\Python311\python.exe" (
  "%LocalAppData%\Programs\Python\Python311\python.exe" "%SCRIPT_DIR%env_inspector.py" %*
  goto :eof
)

echo Python 3 is required. Install Python and try again.
exit /b 1
