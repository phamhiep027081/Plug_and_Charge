$ErrorActionPreference = "Stop"

g++ -std=c++17 -Wall -Wextra -pedantic .\tests\PnC_Flow_Test.cpp -o .\tests\PnC_Flow_Test.exe
.\tests\PnC_Flow_Test.exe
