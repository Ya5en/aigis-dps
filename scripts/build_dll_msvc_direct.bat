@echo off
REM Manual MSVC env (no vcvarsall -- avoids reg.exe).
set "MSVC=C://Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133"
set "SDK=C://Program Files (x86)\Windows Kits\10"
for /f "delims=" %%v in ('dir /b /ad "%SDK%\Include"') do set "SDKVER=%%v"
set "INCLUDE=%MSVC%\include;%SDK%\Include\%SDKVER%\ucrt;%SDK%\Include\%SDKVER%\shared;%SDK%\Include\%SDKVER%\um"
set "LIB=%MSVC%\lib\x86;%SDK%\Lib\%SDKVER%\ucrt\x86;%SDK%\Lib\%SDKVER%\um\x86"
set "PATH=%MSVC%\bin\HostX64\x86;%PATH%"
cd /d "%~dp0.."
if not exist build mkdir build

REM Project version: single source of truth = VERSION file (line 1, semver)
set "DPSVER="
if exist VERSION set /p DPSVER=<VERSION
if not defined DPSVER (
    echo [!] VERSION missing or empty
    exit /b 1
)
echo [ver] %DPSVER%

cl /nologo /LD /O2 /MT /utf-8 /DWIN32_LEAN_AND_MEAN /W3 /Isrc /DDPS_REL_VER=\"%DPSVER%\" /Fo:build\ src\mfplay_proxy.c src\minhook\hook.c src\minhook\buffer.c src\minhook\trampoline.c src\minhook\HDE\hde32.c /Fe:build\mfplay.dll /link /DEF:src\mfplay_proxy.def /IMPLIB:build\mfplay.lib /INCREMENTAL:NO
if errorlevel 1 (
    echo [!] build failed
    exit /b 1
)
echo [ok] build\mfplay.dll
