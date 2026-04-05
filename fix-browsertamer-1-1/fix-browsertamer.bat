@echo off
setlocal

cls
echo.
echo  fix-browsertamer.bat - BrowserTamer setup and association fixer - 1.1
echo  Author: Fabio Lichinchi (mukka) - https://alterego.cc
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

echo  +-----------------------------------------+
echo  ^|  What would you like to do?             ^|
echo  +-----------------------------------------+
echo  ^|  1  Install / fix  (Manual mode)        ^|
echo  ^|  2  Install / fix  (Semi-automatic)     ^|
echo  ^|  3  Uninstall BrowserTamer completely   ^|
echo  ^|  4  Uninstall  (skip confirmation)      ^|
echo  ^|  Q  Quit                                ^|
echo  +-----------------------------------------+
echo.

:ask
set "CHOICE="
set /p "CHOICE=  Enter choice [1/2/3/4/Q]: "

if /i "%CHOICE%"=="1" goto manual
if /i "%CHOICE%"=="2" goto semiauto
if /i "%CHOICE%"=="3" goto uninstall
if /i "%CHOICE%"=="4" goto uninstall_silent
if /i "%CHOICE%"=="Q" goto done
echo   Invalid choice. Please enter 1, 2, 3, 4 or Q.
goto ask

:manual
echo.
echo  Starting in manual mode...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-browsertamer.ps1" -Manual
goto done

:semiauto
echo.
echo  Starting in semi-automatic mode...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-browsertamer.ps1" -SemiAuto
goto done

:uninstall
echo.
echo  Starting uninstaller...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-browsertamer.ps1" -Uninstall
goto done

:uninstall_silent
echo.
echo  Starting uninstaller (no confirmation prompt)...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-browsertamer.ps1" -Uninstall -SemiAuto
goto done

:done
echo.
pause
endlocal
