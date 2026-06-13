$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$cxx = "g++"
if (-not (Get-Command $cxx -ErrorAction SilentlyContinue)) {
    $mingw = "C:\msys64\mingw64\bin\g++.exe"
    if (Test-Path $mingw) {
        $cxx = $mingw
    }
}

$args = @(
    "-std=c++17",
    "-Wall",
    "-Wextra",
    "-Inetxduo/ports/cortex_m7/gnu/inc",
    "-Ithreadx/ports/cortex_m7/gnu/inc",
    "-Inetxduo/common/inc",
    "-Inetxduo/nx_secure/inc",
    "-Inetxduo/crypto_libraries/inc",
    "tests/PnC_Ram_Regression_Test.cpp",
    "-o",
    "tests/PnC_Ram_Regression_Test.exe"
)

& $cxx @args
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& "tests/PnC_Ram_Regression_Test.exe"
exit $LASTEXITCODE
