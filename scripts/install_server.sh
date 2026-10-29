#!/usr/bin/env bash
# Magic Box – Server-Installation (Debian 12/13, Ubuntu 22.04/24.04 – z. B. auf dem PowerEdge R640)
#
#   sudo ./scripts/install_server.sh                       # mit Internet (einmalig), danach offline betreibbar
#   sudo ./scripts/install_server.sh --offline /pfad/bundle # komplett ohne Internet (Bundle aus make_offline_bundle.sh)
#
# Optionen:
#   --model NAME       Ollama-Modell (Standard: qwen3-coder:30b)
#   --no-dotnet        .NET-SDK/ilspycmd nicht installieren (.NET-Metadaten gibt es trotzdem)
#   --no-ollama        Ollama nicht installieren (z. B. wenn der LLM-Server woanders läuft)
#   --llm-url URL      LLM-Server, falls nicht lokal (Standard: http://127.0.0.1:11434)
set -euo pipefail

MODEL="qwen3-coder:30b"
OFFLINE=""
WITH_DOTNET=1
WITH_OLLAMA=1
LLM_URL="http://127.0.0.1:11434"
ILSPY_VERSION="8.2.0.7535"   # läuft mit .NET 8 (getestet)
APP_SRC="$(cd "$(dirname "$0")/.." && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --model) MODEL="$2"; shift 2 ;;
        --offline) OFFLINE="$(cd "$2" && pwd)"; shift 2 ;;
        --no-dotnet) WITH_DOTNET=0; shift ;;
        --no-ollama) WITH_OLLAMA=0; shift ;;
        --llm-url) LLM_URL="$2"; shift 2 ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "Unbekannte Option: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "Bitte mit sudo ausführen." >&2; exit 1; }
step() { printf '\n\033[1;35m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }

HOME_DIR=/opt/magicbox
DATA=/srv/magicbox
CONF=/etc/magicbox

# ------------------------------------------------------------------ Systempakete
DOTNET_DIR=/opt/dotnet

candidate() {  # hat apt für dieses Paket eine installierbare Version?
    local c
    c="$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/{print $2}' || true)"
    [ -n "$c" ] && [ "$c" != "(none)" ]
}

apt_install() {  # installiert, was verfügbar ist – fehlende Pakete nur als Warnung
    local avail=() p
    for p in "$@"; do
        if candidate "$p"; then avail+=("$p"); else warn "Paket $p ist in den Paketquellen nicht verfügbar"; fi
    done
    if [ ${#avail[@]} -gt 0 ]; then apt-get install -y "${avail[@]}"; fi
}

install_radare2_release() {  # radare2 ist z. B. aus Debian entfernt worden → offizielles .deb vom Projekt
    if command -v r2 >/dev/null; then return 0; fi
    if [ "$(dpkg --print-architecture)" != amd64 ]; then warn "radare2: kein passendes .deb für diese Architektur"; return 0; fi
    local url tmp
    url="$(curl -fsSL https://api.github.com/repos/radareorg/radare2/releases/latest 2>/dev/null | python3 -c 'import json,sys
try: assets=json.load(sys.stdin).get("assets",[])
except Exception: assets=[]
for a in assets:
    n=a.get("name","")
    if n.startswith("radare2_") and n.endswith("_amd64.deb"):
        print(a["browser_download_url"]); break' || true)"
    if [ -z "$url" ]; then warn "radare2-Release nicht gefunden – Analyse läuft ohne Pseudocode"; return 0; fi
    tmp="$(mktemp --suffix .deb)"
    if curl -fsSL -o "$tmp" "$url" && apt-get install -y "$tmp"; then
        echo "radare2 installiert ($url)"
    else
        warn "radare2 konnte nicht installiert werden – Analyse läuft ohne Pseudocode"
    fi
    rm -f "$tmp"
}

install_dotnet() {  # .NET 8 SDK für ilspycmd: Paketquelle, sonst Microsofts dotnet-install.sh nach /opt/dotnet
    if command -v dotnet >/dev/null || [ -x "$DOTNET_DIR/dotnet" ]; then return 0; fi
    if candidate dotnet-sdk-8.0; then apt-get install -y dotnet-sdk-8.0; return 0; fi
    echo ".NET 8 SDK nicht in den Paketquellen – installiere es über dotnet-install.sh nach $DOTNET_DIR"
    local inst
    inst="$(mktemp --suffix .sh)"
    if curl -fsSL -o "$inst" https://dot.net/v1/dotnet-install.sh \
        && bash "$inst" --channel 8.0 --install-dir "$DOTNET_DIR" --no-path; then
        register_dotnet
    else
        warn ".NET konnte nicht installiert werden – .NET-Dateien werden nur über Metadaten analysiert"
    fi
    rm -f "$inst"
}

register_dotnet() {  # damit "dotnet" und die ilspycmd-Startdatei die Runtime in /opt/dotnet finden
    ln -sf "$DOTNET_DIR/dotnet" /usr/local/bin/dotnet
    mkdir -p /etc/dotnet
    echo "$DOTNET_DIR" > /etc/dotnet/install_location
}

step "Systempakete"
PKGS=(python3-venv python3-pip git upx-ucl p7zip-full curl rsync)
if [ -n "$OFFLINE" ]; then
    if compgen -G "$OFFLINE/debs/*.deb" > /dev/null; then
        apt-get install -y --no-download "$OFFLINE"/debs/*.deb || dpkg -i "$OFFLINE"/debs/*.deb
    else
        warn "Keine .deb-Pakete im Bundle – setze voraus, dass ${PKGS[*]} schon installiert sind."
    fi
    if [ "$WITH_DOTNET" = 1 ] && [ -d "$OFFLINE/dotnet" ] && [ ! -x "$DOTNET_DIR/dotnet" ]; then
        mkdir -p "$DOTNET_DIR" && cp -a "$OFFLINE"/dotnet/. "$DOTNET_DIR/" && register_dotnet
    fi
else
    apt-get update
    apt_install "${PKGS[@]}"
    if candidate radare2; then apt-get install -y radare2; else install_radare2_release; fi
    if candidate p7zip-rar; then apt-get install -y p7zip-rar
    else warn "p7zip-rar nicht verfügbar – RAR-Archive evtl. nicht entpackbar (Debian: non-free, Ubuntu: multiverse)"; fi
    if [ "$WITH_DOTNET" = 1 ]; then install_dotnet; fi
fi

# ------------------------------------------------------------------ Benutzer & Ordner
step "Benutzer 'magicbox' und Ordner"
id magicbox >/dev/null 2>&1 || useradd --system --create-home --home-dir "$HOME_DIR" --shell /usr/sbin/nologin magicbox
mkdir -p "$DATA"/{daten,eingang,cache,yara} "$CONF" "$HOME_DIR/.dotnet"
rsync -a --delete --exclude .git --exclude .venv --exclude __pycache__ "$APP_SRC"/ "$HOME_DIR/app/" 2>/dev/null \
    || { rm -rf "$HOME_DIR/app"; cp -a "$APP_SRC" "$HOME_DIR/app"; }

# ------------------------------------------------------------------ Python-Umgebung
step "Python-Umgebung"
python3 -m venv "$HOME_DIR/.venv"
PIP="$HOME_DIR/.venv/bin/pip"
if [ -n "$OFFLINE" ]; then
    "$PIP" install --no-index --find-links "$OFFLINE/wheels" -e "$HOME_DIR/app[malware,capa]"
else
    "$PIP" install --upgrade pip
    "$PIP" install -e "$HOME_DIR/app[malware,capa]"
fi

# ------------------------------------------------------------------ capa-Regeln
step "capa-Regeln"
CAPA_VER="$("$HOME_DIR/.venv/bin/pip" show flare-capa 2>/dev/null | awk '/^Version:/{print $2}')"
if [ -n "$OFFLINE" ] && [ -d "$OFFLINE/capa-rules" ]; then
    rm -rf "$HOME_DIR/capa-rules"; cp -a "$OFFLINE/capa-rules" "$HOME_DIR/capa-rules"
elif [ -z "$OFFLINE" ]; then
    rm -rf "$HOME_DIR/capa-rules"
    git clone --depth 1 --branch "v$CAPA_VER" https://github.com/mandiant/capa-rules "$HOME_DIR/capa-rules" 2>/dev/null \
        || git clone --depth 1 https://github.com/mandiant/capa-rules "$HOME_DIR/capa-rules" \
        || warn "capa-Regeln konnten nicht geladen werden – capa wird übersprungen."
fi

# ------------------------------------------------------------------ YARA-Regeln (Community)
step "YARA-Regeln (YARA-Forge core)"
if [ -n "$OFFLINE" ] && [ -d "$OFFLINE/yara" ]; then
    cp -a "$OFFLINE"/yara/. "$DATA/yara/"
elif [ -z "$OFFLINE" ]; then
    TMPZ="$(mktemp --suffix .zip)"
    if curl -fsSL -o "$TMPZ" https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip; then
        python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$TMPZ" "$DATA/yara"
    else
        warn "YARA-Forge-Regeln nicht geladen – nur die mitgelieferten Basisregeln aktiv. Eigene Regeln nach $DATA/yara legen."
    fi
    rm -f "$TMPZ"
fi

# ------------------------------------------------------------------ ilspycmd (.NET-Dekompiler)
if [ "$WITH_DOTNET" = 1 ] && command -v dotnet >/dev/null; then
    step "ilspycmd (.NET-Dekompilierung)"
    SRC_ARGS=()
    [ -n "$OFFLINE" ] && SRC_ARGS=(--add-source "$OFFLINE/nuget")
    chown -R magicbox: "$HOME_DIR/.dotnet"
    DOTNET_ENV=(DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1)
    if [ -x "$DOTNET_DIR/dotnet" ]; then DOTNET_ENV+=(DOTNET_ROOT="$DOTNET_DIR"); fi
    runuser -u magicbox -- env HOME="$HOME_DIR" "${DOTNET_ENV[@]}" \
        dotnet tool install -g ilspycmd --version "$ILSPY_VERSION" "${SRC_ARGS[@]}" \
        || warn "ilspycmd nicht installiert – .NET wird nur über Metadaten analysiert."
fi

# ------------------------------------------------------------------ Ollama
if [ "$WITH_OLLAMA" = 1 ]; then
    step "Ollama + Modell $MODEL"
    if ! command -v ollama >/dev/null; then
        if [ -n "$OFFLINE" ] && [ -f "$OFFLINE/ollama-linux-amd64.tgz" ]; then
            tar -C /usr -xzf "$OFFLINE/ollama-linux-amd64.tgz"
            id ollama >/dev/null 2>&1 || useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
            cat > /etc/systemd/system/ollama.service <<'UNIT'
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
UNIT
        elif [ -z "$OFFLINE" ]; then
            curl -fsSL https://ollama.com/install.sh | sh
        else
            warn "Kein Ollama im Bundle – bitte manuell installieren."
        fi
    fi
    # Ollama bleibt auf localhost: Clients sprechen nur mit der Magic Box (Port 8765), nie direkt mit dem LLM
    mkdir -p /etc/systemd/system/ollama.service.d
    cat > /etc/systemd/system/ollama.service.d/magicbox.conf <<'CONF'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_KEEP_ALIVE=30m"
Environment="OLLAMA_NUM_PARALLEL=1"
CONF
    if [ -n "$OFFLINE" ] && [ -d "$OFFLINE/ollama-models" ]; then
        OLLAMA_MODELS_DIR="$(getent passwd ollama | cut -d: -f6)/.ollama/models"
        mkdir -p "$OLLAMA_MODELS_DIR"
        cp -a "$OFFLINE"/ollama-models/. "$OLLAMA_MODELS_DIR/"
        chown -R ollama: "$(dirname "$OLLAMA_MODELS_DIR")"
    fi
    systemctl daemon-reload
    systemctl enable --now ollama
    sleep 3
    [ -z "$OFFLINE" ] && ollama pull "$MODEL"
    ollama list | grep -q "${MODEL%%:*}" || warn "Modell $MODEL ist nicht vorhanden."
fi

# ------------------------------------------------------------------ Konfiguration
step "Konfiguration ($CONF/settings.json)"
if [ ! -f "$CONF/settings.json" ]; then
    TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
    "$HOME_DIR/.venv/bin/python" - "$CONF/settings.json" "$TOKEN" "$MODEL" "$LLM_URL" "$HOME_DIR" "$DATA" <<'PY'
import sys
from pathlib import Path
from magicbox.config import Settings
path, token, model, url, home, data = sys.argv[1:]
s = Settings(base_url=url, model=model, web_token=token, data_dir=f"{data}/daten", profile="malware",
             audience="für Sicherheitsanalysten (Malware-/Incident-Response-Fokus)",
             capa_path=f"{home}/.venv/bin/capa", capa_rules=f"{home}/capa-rules" if Path(f"{home}/capa-rules").is_dir() else "",
             yara_rules_dir=f"{data}/yara", ilspy_path=f"{home}/.dotnet/tools/ilspycmd")
s.save(Path(path))
PY
    echo "Zugangsschlüssel für die Web-Oberfläche: $TOKEN"
fi
chown -R magicbox: "$DATA" "$CONF" "$HOME_DIR"
chmod 700 "$CONF"; chmod 600 "$CONF/settings.json"

# ------------------------------------------------------------------ Dienst
step "systemd-Dienst"
install -m 644 "$HOME_DIR/app/scripts/magicbox-server.service" /etc/systemd/system/magicbox-server.service
systemctl daemon-reload
systemctl enable --now magicbox-server
sleep 2
systemctl --no-pager --lines=5 status magicbox-server || true

IP="$(hostname -I | awk '{print $1}')"
TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["web_token"])' "$CONF/settings.json")"
cat <<EOF

✅ Fertig.
   Web-Oberfläche:  http://$IP:8765/?token=$TOKEN
   Desktop-App:     magicbox desktop --server http://$IP:8765   (Token wird beim ersten Öffnen abgefragt)
   Drop-Ordner:     $DATA/eingang   (z. B. per Samba freigeben)
   Logs:            journalctl -u magicbox-server -f

   Firewall (empfohlen): nur Port 8765 aus dem LAN erlauben, z. B.
     ufw allow from 192.168.1.0/24 to any port 8765 proto tcp
EOF
