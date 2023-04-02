@echo off
rem ".\3rd party\GoVersionSetter.exe" -i
".\3rd party\GoVersionSetter.exe" -e npm -f ./webclient/micro-vault/package.json

echo build web client
cd webclient\micro-vault
call build.cmd
cd ..
cd ..
