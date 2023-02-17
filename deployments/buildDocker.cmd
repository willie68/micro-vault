@echo off
echo building service
docker build -f ./build/package/Dockerfile ./ -t mcs/microvault-service:V1
docker run --name microvault-service -p 9543:8443 -p 9080:8080 mcs/microvault-service:V1