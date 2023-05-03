@echo off
echo %1
if "%~1"=="" goto simple
if "%~1"=="-v" goto version
goto simple

:version
".\3rd party\GoVersionSetter.exe" -i

:simple
".\3rd party\GoVersionSetter.exe" -e npm -f ./webclient/micro-vault/package.json

echo build web client
cd webclient\micro-vault
call build.cmd
cd ..
cd ..

rem build mvcli
call .\deployments\buildcli.cmd

rem build mv-service
call .\deployments\build.cmd

echo copy to distribution
mkdir .\dist
move /Y .\mvcli.exe .\dist
move /Y .\microvault-service.exe .\dist
