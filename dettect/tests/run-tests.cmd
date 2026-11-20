@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /std:c++17 /EHsc /W4 /utf-8 /Fe:build\echo_tests.exe /Fo:build\echo_tests.obj echo_tests.cpp
if errorlevel 1 exit /b 1
build\echo_tests.exe
exit /b %errorlevel%
