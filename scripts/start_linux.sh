#!/usr/bin/env bash
# Magic Box unter Linux/macOS starten (legt beim ersten Mal eine virtuelle Umgebung an)
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -d .venv ]; then
    echo "Erstelle virtuelle Umgebung …"
    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -e '.[gui]'
fi
exec .venv/bin/python -m magicbox gui "$@"
