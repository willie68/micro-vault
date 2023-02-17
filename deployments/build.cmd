@echo off
echo building service
go build -ldflags="-s -w" -o microvault-service.exe cmd/service/main.go