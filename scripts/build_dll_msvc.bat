@echo off
setlocal
cd /d "%~dp0."

REM ============================================================
REM  Build mfplay.dll (aigis-dps: message-bus hook) with MSVC x86.
REM  Output: ..\build\mfplay.dll
REM  Auto-calls vcvarsall x86; falls back to bare cl.exe if already
REM  running inside an x86 Native Tools prompt.
REM ============================================================

set "ROOT=%~dp0.."
set "OUT=%ROOT%\build"
if not exist "%OUT%" mkdir "%OUT%"

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"

if exist "%VCVARS%" goto :havevc
where cl >nul 2>&1
if errorlevel 1 (
    echo [!] cl.exe not in PATH and vcvarsall.bat not found.
    echo     Run this from "x86 Native Tools Command Prompt for VS 2019".
    exit /b 1
)
goto :build

:havevc
call "%VCVARS%" x86 >nul 2>&1
if errorlevel 1 (
    echo [!] vcvarsall x86 failed
    exit /b 1
)

:build
cl /nologo /LD /O2 /MT /utf-8 /DWIN32_LEAN_AND_MEAN /W3 /Fo:"%OUT%\\" "%ROOT%\src\mfplay_proxy.c" /Fe:"%OUT%\mfplay.dll" /link /DEF:"%ROOT%\src\mfplay_proxy.def" ws2_32.lib user32.lib /IMPLIB:"%OUT%\mfplay.lib" /INCREMENTAL:NO
if errorlevel 1 (
    echo [!] build failed
    exit /b 1
)

echo.
echo [ok] output: %OUT%\mfplay.dll
echo next: copy /y "%OUT%\mfplay.dll" "F:\DMM\aigisr_exe\"
endlocal
