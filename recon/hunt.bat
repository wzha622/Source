@echo off
cd /d "%~dp0.."
where python >nul 2>&1
if errorlevel 1 (
    py "%~dp0cdn_hunter.py" %*
) else (
    python "%~dp0cdn_hunter.py" %*
)
echo.
pause
