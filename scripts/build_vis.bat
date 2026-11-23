@echo off
REM shmvis (SHM block visualization) build -- manual MSVC env, x64, AVX2 in its own TU.
set "MSVC=C://Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133"
set "SDK=C://Program Files (x86)\Windows Kits\10"
for /f "delims=" %%v in ('dir /b /ad "%SDK%\Include"') do set "SDKVER=%%v"
set "INCLUDE=%MSVC%\include;%SDK%\Include\%SDKVER%\ucrt;%SDK%\Include\%SDKVER%\shared;%SDK%\Include\%SDKVER%\um"
set "LIB=%MSVC%\lib\x64;%SDK%\Lib\%SDKVER%\ucrt\x64;%SDK%\Lib\%SDKVER%\um\x64"
set "PATH=%MSVC%\bin\HostX64\x64;%PATH%"
cd /d "%~dp0.."
if not exist build\vis mkdir build\vis

REM --- 1) AVX2 kernel: this TU alone is compiled with /arch:AVX2 ---
cl /nologo /c /O2 /MT /GL /utf-8 /W3 /arch:AVX2 /DWIN32_LEAN_AND_MEAN ^
   /Fo:build\vis\ tools\shmvis\fold_avx2.c
if errorlevel 1 goto fail

REM --- 2) rest: baseline arch (must stay runnable on non-AVX2 CPUs) ---
cl /nologo /c /O2 /MT /GL /utf-8 /W3 /DWIN32_LEAN_AND_MEAN ^
   /Fo:build\vis\ tools\shmvis\shmvis.c tools\shmvis\fold_scalar.c
if errorlevel 1 goto fail

REM --- 3) link ---
cl /nologo /MT /O2 /GL /nologo build\vis\shmvis.obj build\vis\fold_avx2.obj build\vis\fold_scalar.obj ^
   /link /LTCG /INCREMENTAL:NO /SUBSYSTEM:CONSOLE /OUT:build\vis\shmvis.exe ^
   user32.lib gdi32.lib winmm.lib
if errorlevel 1 goto fail

echo [ok] build\vis\shmvis.exe
exit /b 0

:fail
echo [!] build failed
exit /b 1
