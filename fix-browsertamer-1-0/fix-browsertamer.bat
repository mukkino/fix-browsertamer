@echo off
setlocal

cls
echo.
echo fix-browsertamer.bat - BrowserTamer setup and association fixer - 1.0
echo Author: Fabio Lichinchi (mukka) - https://alterego.cc
echo.
echo  IMPORTANT: Run this from a NORMAL (non-elevated) command prompt.
echo  The script requests elevation only for the specific steps that need it.
echo  Running as Administrator will break the default-browser association steps.
echo.

if not exist "%~dp0fix-browsertamer.ps1" (
    echo  ERROR: fix-browsertamer.ps1 not found next to this batch file.
    echo  Both files must be in the same folder.
    echo.
    pause
    exit /b 1
)

echo  Choose how you want to run it:
echo.
echo   [1]  Semi-automatic  - fewer prompts, runs with minimal pauses
echo   [2]  Manual          - pauses at each step so you can read the output
echo   [3]  Exit            - do nothing and close
echo.

:ask
set "CHOICE="
set /p "CHOICE=Enter 1, 2 or 3 and press Enter: "

if "%CHOICE%"=="1" goto semiauto
if "%CHOICE%"=="2" goto manual
if "%CHOICE%"=="3" goto done
echo   Invalid choice. Please enter 1, 2 or 3.
goto ask

:semiauto
echo.
echo  Starting in semi-automatic mode...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-browsertamer.ps1" -SemiAuto
goto done

:manual
echo.
echo  Starting in manual mode...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-browsertamer.ps1" -Manual
goto done

:done
echo.
pause
endlocal
