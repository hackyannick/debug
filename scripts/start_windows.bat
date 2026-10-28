@echo off
rem Magic Box unter Windows starten (legt beim ersten Mal eine virtuelle Umgebung an)
cd /d "%~dp0\.."
if not exist .venv (
    echo Erstelle virtuelle Umgebung ...
    py -3 -m venv .venv || python -m venv .venv
    .venv\Scripts\python -m pip install --upgrade pip
    .venv\Scripts\python -m pip install -e .[gui]
)
start "" .venv\Scripts\pythonw -m magicbox gui
