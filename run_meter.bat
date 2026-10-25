@echo off
set PYTHONPATH=%~dp0src
python -m sds_meter %*
if errorlevel 1 pause
