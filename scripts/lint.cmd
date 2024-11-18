@echo off
cls
revive -config revive.toml -formatter friendly ./... >lint.txt