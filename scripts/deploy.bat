@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 936 >nul 2>&1
title aigis-dps deploy
set "SYS32=%SystemRoot%\System32"

REM ==========================================================================
REM  aigis-dps 部署脚本
REM    把 build\mfplay.dll 替换进游戏目录（旁置代理注入）。
REM
REM  用法：
REM    deploy.bat                  部署（默认游戏目录）
REM    deploy.bat -game D:\xxx     指定游戏目录
REM    deploy.bat -u               卸载（恢复原版 / 移除代理）
REM    deploy.bat -b               部署前先构建
REM    deploy.bat -y               跳过交互确认
REM    deploy.bat -run             部署后启动游戏
REM    deploy.bat -f               跳过游戏运行检查（强制）
REM
REM  可回滚：首次部署会把游戏目录原有的 mfplay.dll 备份为 mfplay.dll.orig，
REM          -u 时自动恢复并删除备份。若目录内本来没有该文件（正常情况，
REM          原件在系统目录），-u 直接删除代理文件即可。
REM ==========================================================================

set "ROOT=%~dp0.."
pushd "%ROOT%" >nul 2>&1
if errorlevel 1 (
    echo [x] 无法进入项目目录: %ROOT%
    exit /b 1
)
set "ROOT=%CD%"
set "SRC=%ROOT%\build\mfplay.dll"
set "RECV=%ROOT%..\aigis-dps-data\recv\dpsrecv2.exe"

set "GAME=%AIGIS_DIR%"
if not defined GAME set "GAME=F:\DMM\aigisr_exe"

set "MODE=deploy"
set "YES=0"
set "BUILD_FIRST=0"
set "RUN_GAME=0"
set "FORCE=0"
set "RUNNING=0"
set "HASH=(未获取)"

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="-u"         goto arg_undeploy
if /i "%~1"=="-uninstall" goto arg_undeploy
if /i "%~1"=="-game"      goto arg_game
if /i "%~1"=="-b"         goto arg_build
if /i "%~1"=="-y"         goto arg_yes
if /i "%~1"=="-run"       goto arg_run
if /i "%~1"=="-f"         goto arg_force
if /i "%~1"=="-h"         goto usage
if /i "%~1"=="-help"      goto usage
echo [x] 未知参数: %~1
goto usage

:arg_undeploy
set "MODE=undeploy"
shift
goto parse

:arg_game
if "%~2"=="" (
    echo [x] -game 后面需要目录路径
    goto usage
)
set "GAME=%~2"
shift
shift
goto parse

:arg_build
set "BUILD_FIRST=1"
shift
goto parse

:arg_yes
set "YES=1"
shift
goto parse

:arg_run
set "RUN_GAME=1"
shift
goto parse

:arg_force
set "FORCE=1"
shift
goto parse

:parsed
set "EXE=%GAME%\Aigis_r.exe"
set "TGT=%GAME%\mfplay.dll"
set "ORIG=%GAME%\mfplay.dll.orig"

if "%MODE%"=="undeploy" goto undeploy

REM ---------------------------------------------------------------- 部署 ----
if "%BUILD_FIRST%"=="1" (
    call "%ROOT%\scripts\build_dll_msvc_direct.bat"
    if errorlevel 1 (
        echo [x] 构建失败，已中止部署
        goto end_fail
    )
)

if not exist "%SRC%" (
    echo [x] 未找到产物: %SRC%
    echo     请先运行 scripts\build_dll_msvc_direct.bat，或加 -b 参数自动构建
    goto end_fail
)
for %%F in ("%SRC%") do set "SRCSIZE=%%~zF"

if not exist "%EXE%" (
    echo [x] 游戏目录无效: %GAME%
    echo     未找到 Aigis_r.exe。用 -game 指定目录，或设置环境变量 AIGIS_DIR。
    goto end_fail
)

call :proc_running
if "%RUNNING%"=="1" (
    if "%FORCE%"=="1" (
        echo [*] 游戏正在运行（%PROC_PATH%），-f 强制继续。复制可能因占用失败。
    ) else (
        echo.
        echo [x] 该游戏目录正在被运行中的进程占用: %PROC_PATH%
        echo     请完全退出游戏后重试；确需强行替换可加 -f（不推荐）。
        goto end_fail
    )
)

REM 首次部署备份原版（目录内本来无该文件属正常，此时不产生备份）
if exist "%TGT%" (
    if not exist "%ORIG%" (
        call :is_ours "%TGT%"
        if errorlevel 1 (
            copy /y "%TGT%" "%ORIG%" >nul
            if errorlevel 1 (
                echo [x] 备份原版失败（权限不足？）
                goto end_fail
            )
            echo [*] 已备份原版: mfplay.dll.orig
        ) else (
            echo [*] 目录内已是本工具 DLL，跳过原版备份
        )
    ) else (
        echo [*] 已有 mfplay.dll.orig，保留最早的原始备份
    )
)

if not "%YES%"=="1" (
    echo.
    echo   源文件: %SRC%
    echo   大小:   %SRCSIZE% 字节
    echo   目标:   %TGT%
    echo.
    "%SYS32%\choice.exe" /c YN /n /m "确认部署? [Y/N] "
    if errorlevel 2 goto cancelled
)

copy /y "%SRC%" "%TGT%" >nul
if errorlevel 1 (
    echo [x] 复制失败（文件占用或权限不足）
    goto end_fail
)

for %%F in ("%TGT%") do set "TGTSIZE=%%~zF"
if not "%SRCSIZE%"=="%TGTSIZE%" (
    echo [x] 校验失败: 源 %SRCSIZE% 字节 / 目标 %TGTSIZE% 字节
    goto end_fail
)
call :sha256 "%TGT%"

echo.
echo [ok] 部署完成
echo      文件:   %TGT%
echo      大小:   %TGTSIZE% 字节
echo      SHA256: %HASH%
echo.
echo 后续步骤:
echo   1) 启动游戏并进入战斗
echo   2) 采集事件:  "%RECV%" -quiet -jsonl battle.jsonl
echo      卡点诊断:  "%RECV%" -diag 5
echo   3) 只想临时停发（不卸载）: set DPS_ON=0 后启动游戏
echo   4) 撤销部署:  scripts\deploy.bat -u

if not exist "%RECV%" (
    echo.
    echo [*] 提示: 接收端尚未构建。在 tools\dpsrecv 目录执行 "go build -o dpsrecv2.exe main.go"
)

if "%RUN_GAME%"=="1" (
    echo.
    echo [*] 启动游戏...
    start "" /d "%GAME%" "%EXE%"
)
goto end_ok

REM ---------------------------------------------------------------- 卸载 ----
:undeploy
if not exist "%TGT%" (
    echo [*] 游戏目录内没有 mfplay.dll，无需卸载
    goto end_ok
)

call :proc_running
if "%RUNNING%"=="1" (
    if "%FORCE%"=="1" (
        echo [*] 游戏正在运行（%PROC_PATH%），-f 强制继续。
    ) else (
        echo [x] 该游戏目录正在被运行中的进程占用: %PROC_PATH%
        echo     请先完全退出游戏；确需强行操作可加 -f（不推荐）。
        goto end_fail
    )
)

if not "%YES%"=="1" (
    echo.
    echo   将要移除: %TGT%
    "%SYS32%\choice.exe" /c YN /n /m "确认卸载? [Y/N] "
    if errorlevel 2 goto cancelled
)

if exist "%ORIG%" (
    copy /y "%ORIG%" "%TGT%" >nul
    if errorlevel 1 (
        echo [x] 恢复原版失败（权限不足？）
        goto end_fail
    )
    del /f /q "%ORIG%" >nul 2>&1
    echo [ok] 已恢复原版 mfplay.dll，并删除备份
    goto end_ok
)

call :is_ours "%TGT%"
if errorlevel 1 (
    echo [x] 该 mfplay.dll 不是本工具产物，且没有 .orig 备份。
    echo     为避免破坏游戏文件，已中止。请手动确认后再删。
    goto end_fail
)

del /f /q "%TGT%"
if errorlevel 1 (
    echo [x] 删除失败（文件占用或权限不足）
    goto end_fail
)
echo [ok] 已移除代理 mfplay.dll（游戏将回落到系统目录原件）
goto end_ok

REM ------------------------------------------------------------ 子程序 ------
REM 只在「运行中的 Aigis_r.exe 确实位于目标目录」时判定为占用，
REM 避免误拦其它副本 / 沙盒目录的操作。
:proc_running
set "RUNNING=0"
set "PROC_PATH="
set "P2=%TEMP%\_dps_proc.tmp"
"%SYS32%\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "(Get-Process -Name Aigis_r -ErrorAction SilentlyContinue | Select-Object -First 1).Path" > "%P2%" 2>nul
if exist "%P2%" (
    for /f "usebackq delims=" %%p in ("%P2%") do if not defined PROC_PATH set "PROC_PATH=%%p"
)
del /f /q "%P2%" >nul 2>&1
if not defined PROC_PATH goto :eof
echo !PROC_PATH! | "%SYS32%\find.exe" /i "%GAME%\" >nul
if not errorlevel 1 set "RUNNING=1"
goto :eof

REM 判定文件是否本工具产物：程序内含 "[dps] init:" 诊断字符串
:is_ours
"%SYS32%\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "try { $s=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes('%~1')); if ($s.Contains('[dps] init:')) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
exit /b %errorlevel%

REM 取 SHA256：certutil 输出重定向到临时文件再读第二行，
REM 避开 for /f 内嵌引号被 cmd 剥离的经典坑。
:sha256
set "HASH=(未获取)"
set "H2=%TEMP%\_dps_hash.tmp"
"%SYS32%\certutil.exe" -hashfile "%~1" SHA256 > "%H2%" 2>nul
if exist "%H2%" (
    for /f "usebackq skip=1 delims=" %%h in ("%H2%") do (
        set "HASH=%%h"
        goto :sha_done
    )
)
:sha_done
del /f /q "%H2%" >nul 2>&1
goto :eof

:usage
echo.
echo 用法:
echo   deploy.bat                 部署到默认游戏目录
echo   deploy.bat -game 目录       指定游戏目录
echo   deploy.bat -b              部署前先构建
echo   deploy.bat -y              跳过确认
echo   deploy.bat -run            部署后启动游戏
echo   deploy.bat -f              跳过游戏运行检查（强制）
echo   deploy.bat -u              卸载并恢复原版
echo.
popd
exit /b 1

:cancelled
echo [*] 已取消
goto end_ok

:end_ok
popd
exit /b 0

:end_fail
popd
exit /b 1
