@echo off
echo building service
swag init -g ./cmd/service/main.go
go build -ldflags="-s -w" -o microvault-service.exe cmd/service/main.go