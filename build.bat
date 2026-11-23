@echo off
rem Build bedrock-bridge and assemble a drop-in Pumpkin plugin folder (Windows).
rem
rem Usage:   build.bat
rem          Builds, runs the unit tests if wasmtime is installed, and packages.
rem Options (set them as environment variables before running):
rem          SKIP_TESTS=1   do not run the unit tests
rem          NO_PAUSE=1     do not wait for a key press at the end (CI, scripts)
rem
rem Output:  dist\bedrock-bridge\              copy its contents into your Pumpkin server folder
rem          dist\bedrock-bridge-VERSION.zip   the same thing, zipped

setlocal EnableExtensions
cd /d "%~dp0"

set "NAME=bedrock-bridge"
set "CRATE=%NAME:-=_%"
set "TARGET=wasm32-wasip2"
set "OUT=dist\%NAME%"

rem Read the package version from Cargo.toml: the first line whose key is exactly "version".
rem (for /f splits on LF as well as CRLF, unlike findstr anchors.)
set "VERSION="
for /f "usebackq tokens=1,* delims== " %%A in ("Cargo.toml") do (
  if not defined VERSION if "%%A"=="version" set "VERSION=%%~B"
)
if not defined VERSION set "VERSION=0.0.0"

where cargo >nul 2>&1
if errorlevel 1 (
  echo error: cargo not found. Install Rust 1.88 or newer from https://rustup.rs >&2
  goto :fail
)
where rustup >nul 2>&1
if errorlevel 1 (
  echo error: rustup not found. Install Rust 1.88 or newer from https://rustup.rs >&2
  goto :fail
)

rem No /x here: findstr anchors do not work reliably on the LF-only output of rustup.
rustup target list --installed | findstr /c:"%TARGET%" >nul 2>&1
if errorlevel 1 (
  echo [build] installing Rust target %TARGET%
  rustup target add %TARGET%
  if errorlevel 1 goto :fail
)

if "%SKIP_TESTS%"=="1" goto :skip_tests
where wasmtime >nul 2>&1
if errorlevel 1 goto :skip_tests
echo [build] running unit tests under wasmtime
set "CARGO_TARGET_WASM32_WASIP2_RUNNER=wasmtime"
cargo test --target %TARGET%
if errorlevel 1 goto :fail
goto :after_tests
:skip_tests
echo [build] skipping unit tests. Install wasmtime to enable them, or set SKIP_TESTS=1 to silence this.
:after_tests

echo [build] building release for %TARGET%
cargo build --release --target %TARGET%
if errorlevel 1 (
  echo.
  echo Tip: if the error says link.exe was not found, install Build Tools for Visual Studio with the "Desktop development with C++" workload, then open a new terminal and run this script again.
  goto :fail
)

rem Cargo turns the hyphens of the crate name into underscores for the artifact name.
set "WASM=target\%TARGET%\release\%CRATE%.wasm"
if not exist "%WASM%" (
  echo error: expected build artifact %WASM% was not produced >&2
  goto :fail
)

rem Sanity check: Pumpkin loads WASM components, not plain core modules. A component starts with
rem the bytes 00 61 73 6D 0D 00 01 00 (magic, version, layer 1); a core module has layer 0.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$b=[IO.File]::ReadAllBytes('%WASM%'); if ($b.Length -gt 8 -and $b[6] -eq 1 -and $b[7] -eq 0) { exit 0 } else { exit 1 }"
if errorlevel 1 (
  echo warning: %WASM% does not look like a WASM component. Pumpkin may refuse to load it. >&2
) else (
  echo [build] output is a WASM component
)

rem Optional full validation when wasm-tools is installed.
where wasm-tools >nul 2>&1
if errorlevel 1 goto :assemble
wasm-tools validate "%WASM%"
if errorlevel 1 goto :fail
echo [build] wasm-tools: validation passed

:assemble
echo [build] assembling %OUT%
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%\plugins\data\%NAME%" || goto :fail
copy /y "%WASM%" "%OUT%\plugins\%NAME%.wasm" >nul || goto :fail
copy /y "config.example.toml" "%OUT%\plugins\data\%NAME%\config.toml" >nul || goto :fail
copy /y "dist-template\pumpkin-config.snippet.toml" "%OUT%\" >nul || goto :fail
copy /y "dist-template\INSTALL.md" "%OUT%\" >nul || goto :fail
copy /y "README.md" "%OUT%\" >nul || goto :fail

set "ZIP=dist\%NAME%-%VERSION%.zip"
if exist "%ZIP%" del /q "%ZIP%"

rem Prefer the tar.exe that ships with Windows 10 and later: it writes portable zip entries
rem with forward slashes. Fall back to PowerShell if it is not there.
if not exist "%SystemRoot%\System32\tar.exe" goto :zip_powershell
"%SystemRoot%\System32\tar.exe" -a -c -f "%ZIP%" -C dist "%NAME%"
if errorlevel 1 goto :fail
goto :done

:zip_powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path 'dist\%NAME%' -DestinationPath '%ZIP%' -Force"
if errorlevel 1 goto :fail

:done
echo.
echo Done:
echo   folder: %OUT%\
echo   zip:    %ZIP%
echo.
echo Next: follow %OUT%\INSTALL.md. The plugin will not start until config.toml is filled in.
call :pause_if_double_clicked
endlocal
exit /b 0

:fail
echo.
echo Build failed. >&2
call :pause_if_double_clicked
endlocal
exit /b 1

:pause_if_double_clicked
rem When started by double-click the window would close before you can read the output.
if defined NO_PAUSE exit /b 0
echo %cmdcmdline% | "%SystemRoot%\System32\find.exe" /i "/c" >nul
if not errorlevel 1 pause
exit /b 0
