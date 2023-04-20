@echo off
rem ".\3rd party\GoVersionSetter.exe" -i
".\3rd party\GoVersionSetter.exe" -e npm -f ./webclient/micro-vault/package.json

echo build web client
cd webclient\micro-vault
call build.cmd
cd ..
cd ..

echo build mvcli
call .\deployments\buildcli.cmd

echo build mv-service
call .\deployments\build.cmd