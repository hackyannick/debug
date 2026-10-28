#!/usr/bin/env bash
# Baut ein Offline-Paket für einen Server OHNE Internetzugang.
#
# Auf einem Rechner MIT Internet ausführen – am besten in einer frischen VM/einem Container mit
# derselben Ubuntu- und Python-Version wie der Zielserver (sonst passen .deb-Pakete und Wheels nicht):
#
#   ./scripts/make_offline_bundle.sh [--model qwen3-coder:30b] [--no-debs] [--no-model]
#
# Ergebnis: magicbox-offline.tar.gz  →  auf den Server kopieren, entpacken und dort ausführen:
#   sudo ./scripts/install_server.sh --offline ./magicbox-offline
set -euo pipefail

MODEL="qwen3-coder:30b"
WITH_DEBS=1
WITH_MODEL=1
ILSPY_VERSION="8.2.0.7535"
while [ $# -gt 0 ]; do
    case "$1" in
        --model) MODEL="$2"; shift 2 ;;
        --no-debs) WITH_DEBS=0; shift ;;
        --no-model) WITH_MODEL=0; shift ;;
        *) echo "Unbekannte Option: $1" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/magicbox-offline"
rm -rf "$OUT"
mkdir -p "$OUT"/{wheels,debs,nuget,yara}
step() { printf '\n\033[1;35m==> %s\033[0m\n' "$*"; }

step "Python-Wheels"
python3 -m pip download -d "$OUT/wheels" pip setuptools wheel
python3 -m pip download -d "$OUT/wheels" "$ROOT[malware,capa]"

if [ "$WITH_DEBS" = 1 ]; then
    step "Systempakete (.deb inkl. Abhängigkeiten)"
    sudo apt-get update
    sudo apt-get install --download-only -y -o Dir::Cache::archives="$OUT/debs" \
        python3-venv python3-pip git radare2 upx-ucl p7zip-full curl dotnet-sdk-8.0
    sudo chown -R "$(id -u):$(id -g)" "$OUT/debs"
    rm -f "$OUT/debs/lock"; rm -rf "$OUT/debs/partial"
fi

step "capa-Regeln"
CAPA_VER="$(python3 -m pip show flare-capa 2>/dev/null | awk '/^Version:/{print $2}')"
CAPA_VER="${CAPA_VER:-$(ls "$OUT/wheels" | sed -n 's/^flare_capa-\([0-9.]*\)-.*/\1/p' | head -1)}"
git clone --depth 1 --branch "v$CAPA_VER" https://github.com/mandiant/capa-rules "$OUT/capa-rules" 2>/dev/null \
    || git clone --depth 1 https://github.com/mandiant/capa-rules "$OUT/capa-rules"
rm -rf "$OUT/capa-rules/.git"

step "YARA-Regeln (YARA-Forge core)"
curl -fsSL -o /tmp/yara-forge.zip https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip \
    && python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" /tmp/yara-forge.zip "$OUT/yara" \
    || echo "[!] YARA-Forge nicht geladen – später manuell nach /srv/magicbox/yara kopieren."

step "ilspycmd (NuGet-Paket)"
curl -fsSL -o "$OUT/nuget/ilspycmd.$ILSPY_VERSION.nupkg" "https://www.nuget.org/api/v2/package/ilspycmd/$ILSPY_VERSION"

step "Ollama"
curl -fsSL -o "$OUT/ollama-linux-amd64.tgz" https://ollama.com/download/ollama-linux-amd64.tgz
if [ "$WITH_MODEL" = 1 ]; then
    if command -v ollama >/dev/null; then
        ollama pull "$MODEL"
        MODELS_DIR="${OLLAMA_MODELS:-$HOME/.ollama/models}"
        [ -d "$MODELS_DIR" ] || MODELS_DIR=/usr/share/ollama/.ollama/models
        mkdir -p "$OUT/ollama-models"
        cp -a "$MODELS_DIR"/. "$OUT/ollama-models/"
    else
        echo "[!] Ollama ist hier nicht installiert – Modell nicht enthalten. Alternativ: Modellordner"
        echo "    (~/.ollama/models bzw. /usr/share/ollama/.ollama/models) von einem anderen Rechner kopieren."
    fi
fi

step "Magic-Box-Quellcode"
mkdir -p "$OUT/magicbox"
tar -C "$ROOT" --exclude .git --exclude .venv --exclude magicbox-offline --exclude '__pycache__' -cf - . | tar -C "$OUT/magicbox" -xf -

tar -C "$ROOT" -czf "$ROOT/magicbox-offline.tar.gz" magicbox-offline
du -sh "$ROOT/magicbox-offline.tar.gz"
cat <<EOF

✅ Bundle fertig: $ROOT/magicbox-offline.tar.gz
   Auf dem Server:
     tar xzf magicbox-offline.tar.gz
     cd magicbox-offline/magicbox && sudo ./scripts/install_server.sh --offline .. --model $MODEL
EOF
