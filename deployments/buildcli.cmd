@echo off
echo building command line client
go build -ldflags="-s -w" -o mvcli.exe cmd/cli/main.go