@echo off
setlocal

g++ -std=c++17 -Wall -Wextra -pedantic .\tests\PnC_Flow_Test.cpp -o .\tests\PnC_Flow_Test.exe
if errorlevel 1 exit /b %errorlevel%

.\tests\PnC_Flow_Test.exe
if errorlevel 1 exit /b %errorlevel%

echo Report generated: %CD%\tests\PnC_Flow_Report.html
