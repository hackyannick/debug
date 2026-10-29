#!/usr/bin/env bash
# ============================================================================
#  🪄 Magic Box – Easy Setup
#
#  Führt Schritt für Schritt durch die komplette Einrichtung mit Ory-Anmeldung:
#
#    1) Auf dem Gateway (hb-s-shieldy: nginx + Ory Hydra/Kratos):
#         sudo ./easy-setup.sh gateway
#       → Hydra-Client, nginx-Site + Zertifikat, Gruppe vergeben, erzeugt magicbox-setup.env
#
#    2) Datei auf den Analyse-Server kopieren:
#         scp magicbox-setup.env r640:~/magicbox/
#
#    3) Auf dem Analyse-Server (R640, im Magic-Box-Repo):
#         sudo ./scripts/easy-setup.sh server
#       → installiert alles, konfiguriert OIDC, Hosts-Eintrag, Firewall, prüft den Login-Weg
#
#  Ohne Ory (nur Zugangsschlüssel, ein einzelner Rechner):
#         sudo ./scripts/easy-setup.sh solo
#
#  Optionen:
#    --env DATEI   Antworten aus/in diese Datei (Standard: ./magicbox-setup.env)
#    --yes         Vorschläge ohne Rückfrage übernehmen (Geheimnisse müssen in der env-Datei stehen)
#    --dry-run     Nichts am System ändern, nur anzeigen, was passieren würde
#
#  Das Skript ist wiederholbar: Ein zweiter Lauf übernimmt die gespeicherten Antworten.
#  Für die Gateway-Rolle reicht diese eine Datei – das restliche Repo wird dort nicht gebraucht.
# ============================================================================
set -euo pipefail

ENV_FILE="./magicbox-setup.env"
YES=0
DRY=0
ROLE=""

# Pfade (für Tests überschreibbar)
NGINX_AVAILABLE="${NGINX_AVAILABLE:-/etc/nginx/sites-available}"
NGINX_ENABLED="${NGINX_ENABLED:-/etc/nginx/sites-enabled}"
LE_DIR="${LE_DIR:-/etc/letsencrypt}"
LE_LIVE="${LE_LIVE:-$LE_DIR/live}"
LE_RENEWAL="${LE_RENEWAL:-$LE_DIR/renewal}"
ACME_WEBROOT=""
CERT_PENDING=0
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
MB_CONF="${MB_CONF:-/etc/magicbox/settings.json}"
MB_VENV="${MB_VENV:-/opt/magicbox/.venv}"
SKIP_ROOT_CHECK="${SKIP_ROOT_CHECK:-0}"

while [ $# -gt 0 ]; do
    case "$1" in
        gateway|server|solo) ROLE="$1"; shift ;;
        --env) ENV_FILE="$2"; shift 2 ;;
        --yes|-y) YES=1; shift ;;
        --dry-run) DRY=1; shift ;;
        -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
        *) echo "Unbekannte Option: $1 (siehe --help)" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------- Ausgabe & Eingabe
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; P=$'\033[35m'; N=$'\033[0m'
else B=""; G=""; Y=""; R=""; P=""; N=""; fi
title() { printf '\n%s━━━ %s ━━━%s\n' "$P$B" "$*" "$N"; }
info()  { printf '  %s\n' "$*"; }
ok()    { printf '  %s✔%s %s\n' "$G" "$N" "$*"; }
warn()  { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()   { printf '\n  %s✖ %s%s\n\n' "$R" "$*" "$N" >&2; exit 1; }

# Antworten vom Terminal lesen – auch wenn das Skript per Pipe gestartet wurde; ohne Terminal von stdin
TTY=/dev/tty
if ! { : < /dev/tty; } 2>/dev/null; then TTY=/dev/stdin; fi

# ask VAR "Frage" "Vorschlag"  – übernimmt bei --yes den Vorschlag bzw. einen schon gesetzten Wert
ask() {
    local var="$1" question="$2" def="${3:-}" cur answer
    cur="${!var:-$def}"
    if [ "$YES" = 1 ]; then printf -v "$var" '%s' "$cur"; info "$question: $cur"; return; fi
    read -r -p "  $question [${cur}]: " answer < "$TTY" || true
    printf -v "$var" '%s' "${answer:-$cur}"
}

# ask_secret VAR "Frage" – leer lassen behält den bekannten Wert
ask_secret() {
    local var="$1" question="$2" answer
    if [ "$YES" = 1 ]; then [ -n "${!var:-}" ] || die "$question fehlt in $ENV_FILE (mit --yes nicht abfragbar)"; return; fi
    local hint=""
    if [ -n "${!var:-}" ]; then hint=" (Enter = bisherigen Wert behalten)"; fi
    read -r -s -p "  $question$hint: " answer < "$TTY" || true
    echo
    if [ -n "$answer" ]; then printf -v "$var" '%s' "$answer"; fi
    [ -n "${!var:-}" ] || die "$question darf nicht leer sein"
}

# confirm "Frage" j|n
confirm() {
    local def="${2:-j}" answer
    if [ "$YES" = 1 ]; then [ "$def" = j ]; return; fi
    read -r -p "  $1 [$([ "$def" = j ] && echo J/n || echo j/N)]: " answer < "$TTY" || true
    answer="${answer:-$def}"
    [[ "$answer" =~ ^[JjYy] ]]
}

# run BEFEHL… – führt Systemänderungen aus (bzw. zeigt sie bei --dry-run nur an)
run() {
    if [ "$DRY" = 1 ]; then printf '  %s[dry-run]%s %s\n' "$Y" "$N" "$*"; return 0; fi
    "$@"
}

need_root() {
    [ "$SKIP_ROOT_CHECK" = 1 ] || [ "$(id -u)" -eq 0 ] || die "Bitte mit sudo ausführen."
}

need_cmd() {
    for c in "$@"; do command -v "$c" >/dev/null || die "Programm '$c' fehlt (apt install $c)."; done
}

# Einstellungen aus/in die env-Datei (nur bekannte Schlüssel, sicher quotiert)
ENV_KEYS=(MB_DOMAIN ID_HOST ISSUER GATEWAY_IP R640_IP CLIENT_ID CLIENT_SECRET TOKEN_AUTH SCOPES GROUP
          POST_LOGOUT HYDRA_ADMIN HYDRA_PUBLIC KRATOS_ADMIN MODEL AUTH_MODE)
load_env() {
    [ -f "$ENV_FILE" ] || return 0
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || continue
        [[ " ${ENV_KEYS[*]} " == *" $key "* ]] || continue
        value="${value%\"}"; value="${value#\"}"
        printf -v "$key" '%s' "$value"
    done < "$ENV_FILE"
    ok "Gespeicherte Antworten aus $ENV_FILE übernommen"
}
save_env() {
    local tmp
    tmp="$(mktemp)"
    {
        echo "# Magic Box – Easy Setup ($(date '+%Y-%m-%d %H:%M')). Enthält das Client-Geheimnis: vertraulich behandeln!"
        for k in "${ENV_KEYS[@]}"; do
            if [ -n "${!k:-}" ]; then printf '%s="%s"\n' "$k" "${!k}"; fi
        done
    } > "$tmp"
    install -m 600 "$tmp" "$ENV_FILE"
    rm -f "$tmp"
    ok "Antworten gespeichert in $ENV_FILE (nur für root lesbar)"
}

json_get() {  # json_get FELD < JSON
    python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for p in sys.argv[1].split("."): d = d.get(p, "") if isinstance(d, dict) else ""
print(" ".join(d) if isinstance(d, list) else d)' "$1"
}

http_code() { curl -s -o /dev/null -w '%{http_code}' "$@" || true; }

# ============================================================================ GATEWAY
role_gateway() {
    title "Magic Box – Gateway einrichten (nginx + Ory Hydra/Kratos)"
    need_root
    need_cmd curl python3 openssl
    load_env

    : "${MB_DOMAIN:=magicbox.hackdv.com}" "${ID_HOST:=id.hackdv.com}" "${CLIENT_ID:=magicbox}" "${GROUP:=magicbox}"
    : "${HYDRA_ADMIN:=http://127.0.0.1:4445}" "${HYDRA_PUBLIC:=http://127.0.0.1:4444}" "${KRATOS_ADMIN:=http://127.0.0.1:4434}"
    : "${GATEWAY_IP:=$(hostname -I 2>/dev/null | awk '{print $1}' || true)}"

    title "1/6  Eckdaten"
    ask MB_DOMAIN "Adresse der Magic Box" "$MB_DOMAIN"
    ask ID_HOST "Adresse des Identitätsanbieters" "$ID_HOST"
    ask GATEWAY_IP "LAN-IP dieses Gateways" "$GATEWAY_IP"
    ask R640_IP "LAN-IP des Analyse-Servers (R640)" "${R640_IP:-}"
    [ -n "$R640_IP" ] || die "LAN-IP des R640 wird benötigt."
    ask GROUP "Kratos-Gruppe für Zugriff (leer = alle Angemeldeten)" "$GROUP"
    ask HYDRA_ADMIN "Hydra Admin API" "$HYDRA_ADMIN"
    ask HYDRA_PUBLIC "Hydra Public API (intern)" "$HYDRA_PUBLIC"
    ask KRATOS_ADMIN "Kratos Admin API" "$KRATOS_ADMIN"
    local redirect="https://$MB_DOMAIN/auth/callback"

    title "2/6  Ory erreichbar?"
    local disc
    disc="$(curl -sf "$HYDRA_PUBLIC/.well-known/openid-configuration" || true)"
    ISSUER="$(printf '%s' "$disc" | json_get issuer)"
    [ -n "$ISSUER" ] || die "Hydra-Discovery unter $HYDRA_PUBLIC nicht lesbar."
    ok "Hydra antwortet, Aussteller: $ISSUER"
    [ "$(http_code "$HYDRA_ADMIN/admin/clients?page_size=1")" = 200 ] || die "Hydra Admin API unter $HYDRA_ADMIN nicht erreichbar."
    ok "Hydra Admin API erreichbar"
    if ! kratos_check "$KRATOS_ADMIN"; then
        local alt=""
        if [ "$YES" = 0 ]; then
            read -r -p "  Andere Adresse für die Kratos Admin API (leer = Gruppen-Schritt überspringen): " alt < "$TTY" || true
        fi
        if [ -n "$alt" ] && kratos_check "$alt"; then
            KRATOS_ADMIN="$alt"
        else
            warn "Gruppen-Schritt wird übersprungen (Gruppe später von Hand setzen, siehe docs/Ory-Anmeldung.md)"
            KRATOS_ADMIN=""
        fi
    fi

    title "3/6  Hydra-Client '$CLIENT_ID'"
    local code
    code="$(http_code "$HYDRA_ADMIN/admin/clients/$CLIENT_ID")"
    if [ "$code" = 200 ]; then
        ok "Client existiert bereits"
        if [ -n "${CLIENT_SECRET:-}" ] && ! confirm "Neues Geheimnis erzeugen (altes wird ungültig)?" n; then
            info "Bisheriges Geheimnis aus $ENV_FILE wird weiterverwendet."
        elif [ -z "${CLIENT_SECRET:-}" ] && ! confirm "Geheimnis ist nicht bekannt – neues erzeugen?" j; then
            ask_secret CLIENT_SECRET "Geheimnis des Clients eingeben"
        else
            CLIENT_SECRET="$(openssl rand -hex 32)"
            client_update_secret
        fi
        client_ensure_redirect "$redirect"
    elif command -v owagate >/dev/null && confirm "Mit 'owagate client add' anlegen (wie eure anderen Clients)?" j; then
        run owagate client add "$CLIENT_ID" "Magic Box" "$redirect"
        if [ "$DRY" = 1 ]; then CLIENT_SECRET="dry-run-geheimnis"
        else ask_secret CLIENT_SECRET "Das eben angezeigte Client-Geheimnis einfügen"; fi
    else
        CLIENT_SECRET="$(openssl rand -hex 32)"
        client_create "$redirect"
    fi
    client_read_settings
    if confirm "Nach dem Abmelden zurück zur Magic Box leiten (post_logout_redirect_uri registrieren)?" j; then
        if client_add_post_logout "https://$MB_DOMAIN/"; then POST_LOGOUT="https://$MB_DOMAIN/"; fi
    fi
    AUTH_MODE="oidc"
    save_env  # sofort sichern: das Client-Geheimnis ist ab jetzt in Hydra gültig

    title "4/6  nginx + Zertifikat für $MB_DOMAIN"
    need_cmd nginx
    detect_acme_webroot
    if setup_certificate; then
        write_nginx_site full
    else
        CERT_PENDING=1
        warn "nginx-Site für $MB_DOMAIN übersprungen, solange das Zertifikat fehlt."
        info "Nach dem Beheben einfach erneut starten – alle Antworten werden übernommen."
    fi

    title "5/6  Zugriff (Gruppe '$GROUP')"
    if [ -n "$GROUP" ] && [ -n "$KRATOS_ADMIN" ]; then
        local emails=""
        ask emails "E-Mail-Adressen, die '$GROUP' bekommen sollen (Komma-getrennt, leer = keine)" ""
        IFS=',' read -r -a list <<< "$emails"
        for e in "${list[@]}"; do
            e="$(echo "$e" | xargs)"
            if [ -n "$e" ]; then kratos_add_group "$e" "$GROUP"; fi
        done
    else
        info "übersprungen"
    fi

    title "6/6  Abschluss"
    if systemctl list-unit-files 2>/dev/null | grep -q '^owa-gate'; then
        if confirm "owa-gate neu starten (CSP form-action übernimmt die neue Callback-Adresse sofort)?" j; then
            run systemctl restart owa-gate
            ok "owa-gate neu gestartet"
        else
            info "Sonst übernimmt owa-gate die Adresse spätestens nach 5 Minuten."
        fi
    fi
    AUTH_MODE="oidc"
    save_env

    cat <<EOF

  $(if [ "$CERT_PENDING" = 1 ]; then echo "${Y}${B}Gateway fast fertig – es fehlt noch das Zertifikat für $MB_DOMAIN (Hinweise oben).${N}"; else echo "${G}${B}Gateway fertig.${N}"; fi)

  Nächste Schritte:
   1. ${B}DNS:${N} $MB_DOMAIN → gleiche öffentliche Adresse wie $ID_HOST
      ${B}im LAN${N} (kein Hairpin-NAT): $MB_DOMAIN und $ID_HOST → $GATEWAY_IP (Router/Pi-hole/AD-DNS)
   2. Datei auf den R640 kopieren:   scp $ENV_FILE <benutzer>@$R640_IP:
   3. Auf dem R640 im Magic-Box-Ordner: sudo ./scripts/easy-setup.sh server --env ~/$(basename "$ENV_FILE")
EOF
}

kratos_admin_exposed() {  # warnt, wenn die Admin API (ohne Authentisierung!) nicht nur auf localhost lauscht
    local port="${1##*:}" addr
    port="${port%%/*}"
    command -v ss >/dev/null || return 0
    while read -r addr; do
        case "$addr" in
            127.*:"$port"|"[::1]:$port"|"") ;;
            *:"$port")
                warn "SICHERHEIT: Kratos Admin API lauscht auf $addr – ohne Authentisierung aus dem Netz erreichbar!"
                info "In /etc/kratos/kratos.yml unter serve.admin 'host: 127.0.0.1' setzen und Kratos neu starten." ;;
        esac
    done < <(ss -ltnpH 2>/dev/null | awk '/kratos/{print $4}' | sort -u || true)
    return 0
}

kratos_check() {  # kratos_check URL – mit Diagnose, wenn es nicht klappt
    local code ports
    kratos_admin_exposed "$1"
    code="$(http_code --max-time 5 "$1/admin/identities")"
    case "$code" in
        200) ok "Kratos Admin API erreichbar ($1)"; return 0 ;;
        000) warn "Kratos Admin API unter $1: keine Verbindung" ;;
        *)   warn "Kratos Admin API unter $1 antwortet mit HTTP $code (erwartet 200)" ;;
    esac
    if command -v ss >/dev/null; then
        ports="$(ss -ltnpH 2>/dev/null | awk '/kratos/{print $4}' | sort -u | tr '\n' ' ' || true)"
        if [ -n "$ports" ]; then info "Kratos lauscht hier auf: $ports"; fi
    fi
    return 1
}

client_json() {  # Basis-JSON für einen neuen Client
    python3 - "$CLIENT_ID" "$CLIENT_SECRET" "$1" <<'PY'
import json, sys
cid, secret, redirect = sys.argv[1:]
print(json.dumps({
    "client_id": cid, "client_name": "Magic Box", "client_secret": secret,
    "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
    "scope": "openid email profile groups offline_access", "redirect_uris": [redirect],
    "token_endpoint_auth_method": "client_secret_basic",
}))
PY
}

client_create() {
    local body
    body="$(client_json "$1")"
    if [ "$DRY" = 1 ]; then run curl -X POST "$HYDRA_ADMIN/admin/clients" "(Client-JSON)"; return; fi
    local res
    res="$(curl -s -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' -d "$body" "$HYDRA_ADMIN/admin/clients")"
    [ "${res##*$'\n'}" = 201 ] || die "Client anlegen fehlgeschlagen: ${res%$'\n'*}"
    ok "Client angelegt (Geheimnis: 64 Hex-Zeichen, steht nur in $ENV_FILE)"
}

client_update_secret() {
    if [ "$DRY" = 1 ]; then run curl -X PUT "$HYDRA_ADMIN/admin/clients/$CLIENT_ID" "(neues Geheimnis)"; return; fi
    local body res
    body="$(curl -sf "$HYDRA_ADMIN/admin/clients/$CLIENT_ID" | python3 -c 'import json,sys
c=json.load(sys.stdin); c["client_secret"]=sys.argv[1]
for k in ("created_at","updated_at","client_secret_expires_at","registration_access_token"): c.pop(k, None)
print(json.dumps(c))' "$CLIENT_SECRET" || true)"
    [ -n "$body" ] || die "Client $CLIENT_ID konnte nicht gelesen werden"
    res="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' -d "$body" \
        "$HYDRA_ADMIN/admin/clients/$CLIENT_ID")"
    [ "$res" = 200 ] || die "Geheimnis setzen fehlgeschlagen (HTTP $res)"
    ok "Neues Client-Geheimnis gesetzt"
}

client_ensure_redirect() {
    local uris
    uris="$(curl -sf "$HYDRA_ADMIN/admin/clients/$CLIENT_ID" | json_get redirect_uris || true)"
    if [[ " $uris " == *" $1 "* ]]; then ok "redirect_uri $1 ist registriert"; return; fi
    warn "redirect_uri $1 fehlt (registriert: ${uris:-keine})"
    confirm "Ergänzen?" j || return 0
    if run curl -sf -X PATCH -H 'Content-Type: application/json' \
        -d "[{\"op\":\"add\",\"path\":\"/redirect_uris/-\",\"value\":\"$1\"}]" \
        "$HYDRA_ADMIN/admin/clients/$CLIENT_ID" -o /dev/null; then
        ok "redirect_uri ergänzt"
    else
        warn "redirect_uri konnte nicht ergänzt werden – bitte von Hand im Client eintragen"
    fi
}

client_add_post_logout() {
    local current
    current="$(curl -sf "$HYDRA_ADMIN/admin/clients/$CLIENT_ID" | json_get post_logout_redirect_uris || true)"
    if [[ " $current " == *" $1 "* ]]; then ok "post_logout_redirect_uri ist registriert"; return 0; fi
    local op="add" path="/post_logout_redirect_uris" value="[\"$1\"]"
    if [ -n "$current" ]; then path="/post_logout_redirect_uris/-"; value="\"$1\""; fi
    if run curl -sf -X PATCH -H 'Content-Type: application/json' -d "[{\"op\":\"$op\",\"path\":\"$path\",\"value\":$value}]" \
        "$HYDRA_ADMIN/admin/clients/$CLIENT_ID" -o /dev/null; then
        ok "post_logout_redirect_uri registriert"
    else
        warn "Konnte post_logout_redirect_uri nicht setzen – Abmelden endet auf Hydras Standardseite"; return 1
    fi
}

client_read_settings() {
    local json
    json="$(curl -sf "$HYDRA_ADMIN/admin/clients/$CLIENT_ID" || true)"
    if [ -z "$json" ]; then
        TOKEN_AUTH="${TOKEN_AUTH:-client_secret_basic}"; SCOPES="${SCOPES:-openid email profile}"
        [ "$DRY" = 1 ] || warn "Client nicht lesbar – Standardwerte für Anmeldemethode/Scopes"
        return
    fi
    TOKEN_AUTH="$(printf '%s' "$json" | json_get token_endpoint_auth_method)"
    TOKEN_AUTH="${TOKEN_AUTH:-client_secret_basic}"
    local allowed
    allowed=" $(printf '%s' "$json" | json_get scope) "
    SCOPES="openid"
    for s in email profile groups; do if [[ "$allowed" == *" $s "* ]]; then SCOPES="$SCOPES $s"; fi; done
    ok "Anmeldemethode am Token-Endpunkt: $TOKEN_AUTH"
    ok "Scopes: $SCOPES"
    [[ "$SCOPES" == *groups* ]] || warn "Scope 'groups' ist für den Client nicht erlaubt – falls der groups-Claim fehlt, im Client ergänzen."
}

resolve_public() {  # A-Record über einen öffentlichen Resolver – vorbei an LAN-DNS/hosts
    if command -v dig >/dev/null; then
        dig +short +time=3 +tries=1 A "$1" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | tail -1 || true
    elif command -v host >/dev/null; then
        host -t A -W 3 "$1" 1.1.1.1 2>/dev/null | awk '/has address/{print $4}' | tail -1 || true
    else  # ohne dig/host: DNS-over-HTTPS bei 1.1.1.1
        curl -s --max-time 5 -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$1&type=A" 2>/dev/null \
            | python3 -c 'import json,sys
try: a=[x["data"] for x in json.load(sys.stdin).get("Answer",[]) if x.get("type")==1]
except Exception: a=[]
print(a[-1] if a else "")' || true
    fi
}

dns_report() {
    local pub_id pub_mb loc_mb
    loc_mb="$(getent ahostsv4 "$MB_DOMAIN" | awk 'NR==1{print $1}' || true)"
    pub_id="$(resolve_public "$ID_HOST")"
    pub_mb="$(resolve_public "$MB_DOMAIN")"
    if [ -z "$pub_id$pub_mb" ]; then
        info "Öffentliches DNS nicht prüfbar (1.1.1.1 nicht erreichbar)."
    elif [ -z "$pub_mb" ]; then
        warn "Öffentlich löst $MB_DOMAIN nicht auf – A-Eintrag auf ${pub_id:-die öffentliche IP} anlegen (wie $ID_HOST)."
    elif [ -n "$pub_id" ] && [ "$pub_mb" != "$pub_id" ]; then
        warn "Öffentlich: $MB_DOMAIN → $pub_mb, aber $ID_HOST → $pub_id. Für das Zertifikat muss $MB_DOMAIN auf $pub_id zeigen."
    else
        ok "Öffentliches DNS: $MB_DOMAIN → $pub_mb (wie $ID_HOST)"
    fi
    if [ -n "$loc_mb" ] && [ "$loc_mb" = "$GATEWAY_IP" ]; then
        ok "LAN-DNS: $MB_DOMAIN → $GATEWAY_IP (dieses Gateway)"
    elif [ -n "$loc_mb" ] && [ "$loc_mb" != "$pub_mb" ]; then
        warn "Im LAN zeigt $MB_DOMAIN auf $loc_mb – dieses Gateway ist aber $GATEWAY_IP."
        info "LAN-DNS bzw. hosts-Eintrag auf $GATEWAY_IP ändern, sonst landen Browser und Desktop-App im LAN woanders."
        info "(Für das Zertifikat zählt nur der öffentliche Eintrag.)"
    fi
}

renewal_value() {  # renewal_value DATEI SCHLÜSSEL – Wert aus einer certbot-renewal-Datei
    awk -F' *= *' -v k="$2" '$1==k{gsub(/,/, "", $2); print $2; exit}' "$1" 2>/dev/null | xargs || true
}

# Webroot, über den Let's Encrypt prüft – aus der certbot-Konfiguration der Magic Box bzw. des Identitätsanbieters
detect_acme_webroot() {
    local conf
    for conf in "$LE_RENEWAL/$MB_DOMAIN.conf" "$LE_RENEWAL/$ID_HOST.conf"; do
        if [ ! -f "$conf" ] || [ "$(renewal_value "$conf" authenticator)" != webroot ]; then continue; fi
        ACME_WEBROOT="$(renewal_value "$conf" webroot_path)"
        if [ -z "$ACME_WEBROOT" ]; then ACME_WEBROOT="$(renewal_value "$conf" "$ID_HOST")"; fi
        if [ -n "$ACME_WEBROOT" ]; then return 0; fi
    done
    return 0
}

certbot_has_nginx() {
    certbot plugins --prepare 2>/dev/null | grep -qE '^\* nginx'
}

setup_certificate() {
    if [ -f "$LE_LIVE/$MB_DOMAIN/fullchain.pem" ]; then ok "Zertifikat vorhanden"; return 0; fi
    need_cmd certbot
    dns_report
    local id_auth=""
    if [ -f "$LE_RENEWAL/$ID_HOST.conf" ]; then id_auth="$(renewal_value "$LE_RENEWAL/$ID_HOST.conf" authenticator)"; fi

    if [ -n "$ACME_WEBROOT" ]; then
        info "Zertifikat per Webroot ($ACME_WEBROOT) – wie bei $ID_HOST"
        # Erst nur Port 80 (für die Prüfung durch Let's Encrypt), HTTPS folgt nach dem Zertifikat
        write_nginx_site http
        if ! run certbot certonly --webroot -w "$ACME_WEBROOT" -d "$MB_DOMAIN" --non-interactive --keep-until-expiring; then
            warn "certbot (Webroot) fehlgeschlagen – meist zeigt das öffentliche DNS noch nicht auf das Gateway."
            return 1
        fi
    else
        if ! certbot_has_nginx; then
            if [ -n "$id_auth" ]; then
                info "$ID_HOST nutzt bei certbot das Verfahren '$id_auth' – das übernimmt das Skript nicht automatisch."
            fi
            if confirm "certbot-Plugin für nginx installieren (apt install python3-certbot-nginx)?" j; then
                if ! run apt-get install -y python3-certbot-nginx; then warn "Installation fehlgeschlagen"; return 1; fi
            else
                warn "Bitte das Zertifikat selbst ausstellen: certbot certonly --${id_auth:-webroot} -d $MB_DOMAIN"
                return 1
            fi
        fi
        info "Zertifikat über das nginx-Plugin von certbot"
        if ! run certbot certonly --nginx -d "$MB_DOMAIN" --non-interactive --keep-until-expiring; then
            warn "certbot fehlgeschlagen – meist zeigt das öffentliche DNS noch nicht auf das Gateway."
            return 1
        fi
    fi
    ok "Zertifikat ausgestellt"
}

write_nginx_site() {  # write_nginx_site http|full
    local mode="${1:-full}" site="$NGINX_AVAILABLE/magicbox.conf" tmp backup="" acme=""
    tmp="$(mktemp)"
    if [ -n "$ACME_WEBROOT" ]; then
        acme="    location ^~ /.well-known/acme-challenge/ { root $ACME_WEBROOT; }"
    fi
    cat > "$tmp" <<EOF
# Magic Box – erzeugt von easy-setup.sh (bei Änderungen wird eine Sicherung angelegt)
server {
    listen 80;
    listen [::]:80;
    server_name $MB_DOMAIN;
$acme
    location / { return 301 https://\$host\$request_uri; }
}
EOF
    if [ "$mode" = full ]; then cat >> "$tmp" <<EOF

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $MB_DOMAIN;

    ssl_certificate     $LE_LIVE/$MB_DOMAIN/fullchain.pem;
    ssl_certificate_key $LE_LIVE/$MB_DOMAIN/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 2g;
    proxy_request_buffering off;

    location = /api/events {
        proxy_pass http://$R640_IP:8765;
        proxy_set_header Host              \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }

    location / {
        proxy_pass http://$R640_IP:8765;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
EOF
    fi
    if [ -f "$site" ] && cmp -s "$tmp" "$site"; then ok "nginx-Site unverändert"; rm -f "$tmp"; return; fi
    if [ -f "$site" ]; then
        backup="$site.bak-$(date +%Y%m%d%H%M%S)"
        run cp -a "$site" "$backup"
        info "Bisherige Site gesichert: $backup"
    fi
    run install -m 644 "$tmp" "$site"
    rm -f "$tmp"
    [ -e "$NGINX_ENABLED/magicbox.conf" ] || run ln -s "$site" "$NGINX_ENABLED/magicbox.conf"
    if [ "$DRY" = 1 ] || nginx -t 2>/dev/null; then
        run systemctl reload nginx
        if [ "$mode" = full ]; then ok "nginx-Site aktiv: https://$MB_DOMAIN → $R640_IP:8765"
        else ok "Vorläufige nginx-Site (nur Port 80 für Let's Encrypt) aktiv"; fi
    else
        nginx -t || true
        warn "nginx -t schlägt fehl – Änderung wird zurückgenommen"
        if [ -n "$backup" ]; then run cp -a "$backup" "$site"; else run rm -f "$NGINX_ENABLED/magicbox.conf" "$site"; fi
        die "nginx-Konfiguration fehlerhaft (siehe nginx -t). Bestehende Sites wurden nicht verändert."
    fi
}

kratos_add_group() {  # kratos_add_group EMAIL GRUPPE
    local email="$1" group="$2" ident id patch
    ident="$(curl -sf "$KRATOS_ADMIN/admin/identities?credentials_identifier=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$email")" || true)"
    id="$(printf '%s' "$ident" | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
print(d[0]["id"] if d else "")')"
    if [ -z "$id" ]; then warn "$email: keine Identität gefunden (erst einmal anmelden/registrieren lassen)"; return; fi
    patch="$(printf '%s' "$ident" | python3 -c 'import json,sys
d=json.load(sys.stdin)[0]; g=sys.argv[1]
groups=d.get("traits",{}).get("groups")
if isinstance(groups, list) and g in groups: print("")
elif isinstance(groups, list): print(json.dumps([{"op":"add","path":"/traits/groups/-","value":g}]))
else: print(json.dumps([{"op":"add","path":"/traits/groups","value":[g]}]))' "$group")"
    if [ -z "$patch" ]; then ok "$email ist bereits in '$group'"; return; fi
    if run curl -sf -X PATCH -H 'Content-Type: application/json' -d "$patch" "$KRATOS_ADMIN/admin/identities/$id" -o /dev/null; then
        ok "$email → Gruppe '$group' (wirkt ab der nächsten Anmeldung)"
    else
        warn "$email: Gruppe konnte nicht gesetzt werden (Identity-Schema erlaubt evtl. kein traits.groups)"
    fi
}

# ============================================================================ SERVER (R640)
role_server() {
    local auth="${1:-oidc}"
    title "Magic Box – Analyse-Server einrichten"
    need_root
    need_cmd curl python3
    local repo
    repo="$(cd "$(dirname "$0")/.." && pwd)"
    [ -x "$repo/scripts/install_server.sh" ] || die "Bitte aus dem Magic-Box-Ordner starten (scripts/install_server.sh fehlt)."
    load_env
    AUTH_MODE="${AUTH_MODE:-$auth}"
    if [ "$auth" = token ]; then AUTH_MODE=token; fi

    title "1/6  Anmeldung"
    if [ "$AUTH_MODE" = oidc ]; then
        [ -n "${CLIENT_SECRET:-}" ] || warn "Keine Gateway-Daten gefunden – zuerst 'easy-setup.sh gateway' auf dem Gateway ausführen."
        : "${MB_DOMAIN:=magicbox.hackdv.com}" "${ID_HOST:=id.hackdv.com}" "${CLIENT_ID:=magicbox}" "${GROUP:=magicbox}"
        ask MB_DOMAIN "Adresse der Magic Box" "$MB_DOMAIN"
        ask ID_HOST "Identitätsanbieter" "$ID_HOST"
        ask ISSUER "Aussteller (issuer)" "${ISSUER:-https://$ID_HOST/}"
        ask GATEWAY_IP "LAN-IP des Gateways (nginx/Hydra)" "${GATEWAY_IP:-}"
        ask CLIENT_ID "OIDC-Client-ID" "$CLIENT_ID"
        ask_secret CLIENT_SECRET "OIDC-Client-Geheimnis"
        ask GROUP "Benötigte Gruppe (leer = alle Angemeldeten)" "$GROUP"
        : "${TOKEN_AUTH:=client_secret_basic}" "${SCOPES:=openid email profile groups}"
    else
        info "Anmeldung per Zugangsschlüssel (wird automatisch erzeugt)."
    fi

    title "2/6  KI-Modell"
    local ram_gb
    ram_gb="$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo || echo 0)"
    local suggest="qwen2.5-coder:7b"
    if [ "$ram_gb" -ge 96 ]; then suggest="qwen3-coder:30b"; info "${ram_gb} GB RAM – auch gpt-oss:120b wäre möglich (langsamer, gründlicher)."
    elif [ "$ram_gb" -ge 32 ]; then suggest="qwen3-coder:30b"
    elif [ "$ram_gb" -ge 16 ]; then suggest="qwen2.5-coder:14b"; fi
    info "Erkannt: ${ram_gb} GB RAM, $(nproc) Kerne$(grep -q avx512f /proc/cpuinfo && echo ', AVX-512')"
    ask MODEL "Modell" "${MODEL:-$suggest}"

    title "3/6  Installation (dauert – Modell-Download je nach Größe mehrere Minuten)"
    local args=(--model "$MODEL")
    local bundle=""
    # Offline-Bundle: magicbox-offline/{wheels,debs,…} mit dem Repo in magicbox-offline/magicbox
    if [ -d "$repo/../wheels" ]; then bundle="$(cd "$repo/.." && pwd)"; fi
    if [ -n "$bundle" ] && confirm "Offline-Paket gefunden ($bundle) – ohne Internet installieren?" j; then args+=(--offline "$bundle"); fi
    run "$repo/scripts/install_server.sh" "${args[@]}"

    title "4/6  Konfiguration"
    if [ "$AUTH_MODE" = oidc ]; then
        configure_hosts
        local internal=""
        check_endpoints || internal="$(choose_internal_base)"
        write_settings "$internal"
    fi
    run systemctl restart magicbox-server
    ok "magicbox-server neu gestartet"

    title "5/6  Firewall"
    configure_firewall

    title "6/6  Selbsttest"
    self_test
    save_env
    summary
}

configure_hosts() {
    [ -n "${GATEWAY_IP:-}" ] || { warn "Keine Gateway-IP – Hosts-Eintrag übersprungen"; return; }
    local line="$GATEWAY_IP $ID_HOST $MB_DOMAIN  # magicbox-easy-setup (kein Hairpin-NAT)"
    if grep -q "magicbox-easy-setup" "$HOSTS_FILE" 2>/dev/null; then
        if grep -qF "$line" "$HOSTS_FILE"; then ok "Hosts-Eintrag vorhanden"; return; fi
        run sed -i '/magicbox-easy-setup/d' "$HOSTS_FILE"
    elif grep -qE "^[^#]*[[:space:]]$ID_HOST([[:space:]]|$)" "$HOSTS_FILE" 2>/dev/null; then
        warn "$HOSTS_FILE enthält schon einen Eintrag für $ID_HOST – bleibt unverändert"; return
    fi
    if [ "$DRY" = 1 ]; then run "echo '$line' >> $HOSTS_FILE"; else echo "$line" >> "$HOSTS_FILE"; fi
    ok "Hosts-Eintrag: $ID_HOST, $MB_DOMAIN → $GATEWAY_IP"
}

check_endpoints() {
    local base="${ISSUER%/}" okay=0 disc
    disc="$(curl -s --max-time 10 "$base/.well-known/openid-configuration" || true)"
    if [ "$(printf '%s' "$disc" | json_get issuer)" != "" ]; then ok "Discovery über $base erreichbar"
    else warn "Discovery über $base nicht erreichbar"; okay=1; fi
    if curl -s --max-time 10 "$base/.well-known/jwks.json" | grep -q '"keys"'; then ok "JWKS erreichbar"
    else warn "JWKS nicht erreichbar"; okay=1; fi
    local tc
    tc="$(http_code --max-time 10 -X POST "$base/oauth2/token")"
    case "$tc" in
        400|401) ok "Token-Endpunkt erreichbar (HTTP $tc wie erwartet)" ;;
        *) warn "Token-Endpunkt liefert HTTP $tc (erwartet 400/401) – hängt evtl. hinter dem Captcha-Gate"; okay=1 ;;
    esac
    return $okay
}

choose_internal_base() {
    warn "Der R640 erreicht Hydra über $ISSUER nicht vollständig."
    info "Alternative: Hydra-Public-Port des Gateways direkt (dort für $(hostname -I | awk '{print $1}') freigeben)."
    local alt="http://${GATEWAY_IP:-127.0.0.1}:4444"
    ask alt "Interne Hydra-Adresse (leer = nicht nutzen)" "$alt" >&2
    if [ -n "$alt" ] && curl -sf --max-time 10 "$alt/.well-known/openid-configuration" >/dev/null; then
        ok "Hydra intern erreichbar: $alt" >&2
        echo "$alt"
    else
        warn "Auch $alt nicht erreichbar – Anmeldung wird erst funktionieren, wenn eins der beiden geht." >&2
        echo ""
    fi
}

write_settings() {
    local internal="$1"
    if [ "$DRY" = 1 ]; then run "settings.json: auth_mode=oidc, public_url=https://$MB_DOMAIN, …"; return; fi
    [ -f "$MB_CONF" ] || die "$MB_CONF fehlt – ist install_server.sh durchgelaufen?"
    # Werte per Umgebung übergeben (nicht in den Quelltext einsetzen – Geheimnisse können Sonderzeichen enthalten)
    MB_DOMAIN="$MB_DOMAIN" ISSUER="$ISSUER" INTERNAL="$internal" CLIENT_ID="$CLIENT_ID" CLIENT_SECRET="$CLIENT_SECRET" \
    SCOPES="$SCOPES" TOKEN_AUTH="$TOKEN_AUTH" POST_LOGOUT="${POST_LOGOUT:-}" GROUP="$GROUP" \
    python3 - "$MB_CONF" <<'PY'
import json, os, sys
e = os.environ
p = sys.argv[1]
s = json.load(open(p, encoding="utf-8"))
s.update({
    "auth_mode": "oidc",
    "public_url": "https://" + e["MB_DOMAIN"],
    "oidc_issuer": e["ISSUER"],
    "oidc_internal_base": e["INTERNAL"],
    "oidc_client_id": e["CLIENT_ID"],
    "oidc_client_secret": e["CLIENT_SECRET"],
    "oidc_scopes": e["SCOPES"],
    "oidc_token_auth": e["TOKEN_AUTH"],
    "oidc_post_logout_uri": e["POST_LOGOUT"],
    "auth_groups": [e["GROUP"]] if e["GROUP"] else [],
    "web_token": "",
})
json.dump(s, open(p, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
PY
    chmod 600 "$MB_CONF"
    ok "Anmeldung über $ISSUER eingetragen (Gruppe: ${GROUP:-alle})"
}

lan_network() {  # Netz der ersten LAN-Schnittstelle, z. B. 10.0.201.0/24
    local addr
    addr="$(ip -o -f inet addr show scope global 2>/dev/null | awk 'NR==1{print $4}' || true)"
    [ -n "$addr" ] || return 0
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$addr"
}

configure_firewall() {
    if ! command -v ufw >/dev/null; then warn "ufw nicht installiert – Firewall bitte selbst einrichten (Port 8765 nur vom Gateway)"; return; fi
    local ssh_from="${SSH_CLIENT:-}"; ssh_from="${ssh_from%% *}"
    if [ "$AUTH_MODE" = oidc ] && [ -n "${GATEWAY_IP:-}" ]; then
        run ufw allow from "$GATEWAY_IP" to any port 8765 proto tcp comment 'Magic Box via Gateway' >/dev/null
        ok "Port 8765 nur vom Gateway $GATEWAY_IP"
    else
        local lan
        lan="$(lan_network)"
        ask lan "Netz, aus dem die Magic Box erreichbar sein soll" "$lan"
        run ufw allow from "$lan" to any port 8765 proto tcp comment 'Magic Box LAN' >/dev/null
        ok "Port 8765 aus $lan"
    fi
    if [ -n "$ssh_from" ]; then
        run ufw allow from "$ssh_from" to any port 22 proto tcp comment 'SSH (easy-setup)' >/dev/null
        ok "SSH von $ssh_from bleibt erlaubt"
    fi
    if ! ufw status | grep -q "Status: active"; then
        if confirm "Firewall (ufw) einschalten? Eingehend wird dann alles außer den Regeln oben blockiert." j; then
            run ufw default deny incoming >/dev/null
            run ufw --force enable >/dev/null
            ok "ufw aktiv"
        fi
    fi
    if confirm "Ausgehenden Verkehr sperren (nur noch Gateway, DNS und LAN)? Danach keine Updates aus dem Internet." n; then
        local lan_net
        lan_net="$(lan_network)"
        run ufw allow out to "$lan_net" comment 'LAN' >/dev/null
        run ufw allow out 53 comment 'DNS' >/dev/null
        run ufw default deny outgoing >/dev/null
        ok "Ausgehend gesperrt (außer $lan_net und DNS)"
    fi
}

self_test() {
    if [ "$DRY" = 1 ]; then info "(dry-run: kein Selbsttest)"; return; fi
    local i
    for i in $(seq 1 20); do curl -s -o /dev/null http://127.0.0.1:8765/static/app.css && break; sleep 1; done
    systemctl is-active --quiet magicbox-server && ok "Dienst läuft" || { warn "Dienst läuft nicht:"; journalctl -u magicbox-server -n 20 --no-pager; return; }
    if [ "$AUTH_MODE" = oidc ]; then
        local loc
        loc="$(curl -s -o /dev/null -w '%{redirect_url}' -H "Host: $MB_DOMAIN" http://127.0.0.1:8765/auth/login || true)"
        if [[ "$loc" == https://*"/oauth2/auth?"* ]]; then ok "Login-Weiterleitung zu Hydra funktioniert"
        else warn "Login-Weiterleitung unerwartet: ${loc:-keine} (journalctl -u magicbox-server -n 30)"; fi
    fi
    if "$MB_VENV/bin/magicbox" check --url http://127.0.0.1:11434 --model "$MODEL" >/dev/null 2>&1; then
        ok "KI-Modell $MODEL bereit"
    else
        warn "KI-Modell $MODEL noch nicht bereit (ollama list prüfen)"
    fi
}

summary() {
    local ip
    ip="$(hostname -I | awk '{print $1}')"
    echo
    echo "  ${G}${B}Fertig – die Magic Box ist eingerichtet.${N}"
    echo
    if [ "$AUTH_MODE" = oidc ]; then
        echo "  Öffnen:        https://$MB_DOMAIN"
        echo "  Desktop-App:   Magic Box → Server wechseln … → https://$MB_DOMAIN"
        if [ -n "$GROUP" ]; then echo "  Zugriff:       alle mit Kratos-Gruppe '$GROUP'"; fi
    else
        local token
        token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("web_token",""))' "$MB_CONF" 2>/dev/null || true)"
        echo "  Öffnen:        http://$ip:8765/?token=$token"
    fi
    echo "  Drop-Ordner:   /srv/magicbox/eingang"
    echo "  Logs:          journalctl -u magicbox-server -f"
    echo
}

# ============================================================================ Start
if [ -z "$ROLE" ]; then
    echo
    echo "  ${P}${B}🪄 Magic Box – Easy Setup${N}"
    echo
    echo "   1) gateway  – auf hb-s-shieldy (nginx + Ory): Client, Zertifikat, Gruppe"
    echo "   2) server   – auf dem R640: Analyse-Server mit Ory-Anmeldung"
    echo "   3) solo     – ein einzelner Rechner, Anmeldung per Zugangsschlüssel"
    echo
    read -r -p "  Auswahl [2]: " choice < "$TTY" || true
    case "${choice:-2}" in 1|gateway) ROLE=gateway ;; 3|solo) ROLE=solo ;; *) ROLE=server ;; esac
fi
if [ "$DRY" = 1 ]; then warn "Probelauf (--dry-run): Es wird nichts am System geändert."; fi

case "$ROLE" in
    gateway) role_gateway ;;
    server) role_server oidc ;;
    solo) role_server token ;;
esac
