@echo off
setlocal
cd /d "%~dp0\.."

set "CXX=g++"
where %CXX% >nul 2>nul
if errorlevel 1 (
    if exist "C:\msys64\mingw64\bin\g++.exe" (
        set "CXX=C:\msys64\mingw64\bin\g++.exe"
    )
)

set "NETX_PORT_INC=netxduo\ports\cortex_m7\gnu\inc"
set "THREADX_PORT_INC=threadx\ports\cortex_m7\gnu\inc"

"%CXX%" -std=c++17 -Wall -Wextra ^
    -I"%NETX_PORT_INC%" ^
    -I"%THREADX_PORT_INC%" ^
    -Inetxduo\common\inc ^
    -Inetxduo\nx_secure\inc ^
    -Inetxduo\crypto_libraries\inc ^
    tests\PnC_Ram_Regression_Test.cpp ^
    -o tests\PnC_Ram_Regression_Test.exe
if errorlevel 1 exit /b 1

tests\PnC_Ram_Regression_Test.exe
exit /b %errorlevel%
