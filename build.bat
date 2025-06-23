@echo off
setlocal enabledelayedexpansion

REM Build script for Jarget Agent on Windows
echo Building Jarget Agent...

REM Clean up previous builds
if exist *.class del *.class
if exist jarget.jar del jarget.jar
if exist manifest.txt del manifest.txt

REM Create the manifest file
echo Premain-Class: jarget.JargetAgent > manifest.txt
echo Main-Class: jarget.JargetAgent >> manifest.txt

REM Compile the agent
echo Compiling Jarget Agent...
javac jarget\JargetAgent.java
if errorlevel 1 (
    echo Compilation failed!
    pause
    exit /b 1
)

REM Create the JAR file
echo Creating jarget.jar...
jar cfm jarget.jar manifest.txt jarget\*.class
if errorlevel 1 (
    echo JAR creation failed!
    pause
    exit /b 1
)

REM Clean up temporary files
del jarget\*.class
del manifest.txt

echo Build complete! jarget.jar is ready to use.
echo.
echo Usage: java -javaagent:jarget.jar YourScript.java
echo.
echo Example script with dependencies:
echo // @dep org.apache.commons:commons-lang3:3.12.0
echo // @jar libs\mylib.jar
echo // @dir external-libs\
echo // @url https://repo1.maven.org/maven2/org/json/json/20210307/json-20210307.jar
