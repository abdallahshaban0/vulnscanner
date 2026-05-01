@echo off
REM ============================================================
REM  VulnScanner — Windows launcher
REM  Run: vulnscanner.bat -t example.com --full
REM ============================================================

SET SCRIPT_DIR=%~dp0

REM Auto-activate venv if it exists
IF EXIST "%SCRIPT_DIR%.venv\Scripts\activate.bat" (
    CALL "%SCRIPT_DIR%.venv\Scripts\activate.bat"
)

python "%SCRIPT_DIR%scanner.py" %*
