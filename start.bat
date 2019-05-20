@echo off
set working_dir=%CD%
cd %CD%\venv\Scripts
Call activate
cd %working_dir%
python run.py