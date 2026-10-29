# Anmeldung über deinen Ory-Stack

Die Magic Box gibt die Anmeldung an Ory ab: gleicher Login wie für OWA, aufgaben-api und TLH – mit vorgeschaltetem
Captcha (owa-gate), Kratos-Passwort und TOTP. Die Magic Box selbst kennt keine Passwörter.

| `auth_mode` | Wann | Für deinen Stack |
|---|---|---|
| **`oidc`** | Magic Box ist OIDC-Client bei **Hydra** (wie owa-client, aufgaben-api, tlh-api) | ✅ **empfohlen** – keine Änderung an Kratos nötig |
| `kratos` | Magic Box liest das Kratos-Session-Cookie direkt | nur mit Cookie-Domain `.hackdv.com` (würde alle Sitzungen beenden) |
| `oathkeeper` | Oathkeeper davor, Magic Box prüft dessen ID-Token | entfällt (kein Oathkeeper im Einsatz) |
| `token` | Zugangsschlüssel (Standard) | für Skripte zusätzlich nutzbar |

Einstellungen stehen in `/etc/magicbox/settings.json` (bewusst nicht über die Web-Oberfläche änderbar), danach
`sudo systemctl restart magicbox-server`.

---

## OIDC gegen Hydra (empfohlen)

### Aufbau

```
Browser / Desktop-App
   │  https://magicbox.hackdv.com
   ▼
nginx auf hb-s-shieldy (TLS, wie für id.hackdv.com)
   │  proxy_pass → R640:8765
   ▼
Magic Box auf dem R640 ──(Discovery, Token, JWKS)──► Hydra
   ▲
   └── Login: Browser → id.hackdv.com/oauth2/auth → owa-gate (Captcha) → Kratos (Passwort + TOTP)
       → Consent → zurück nach https://magicbox.hackdv.com/auth/callback
```

**Die Magic Box läuft auf dem R640, nicht auf hb-s-shieldy.** shieldy ist euer Identitäts- und Exchange-Vorposten –
Schadsoftware-Proben (und Analysewerkzeuge, die sie parsen) gehören nicht auf diesen Host. nginx auf shieldy reicht
nur durch.

Ablauf im Detail: Authorization Code Flow mit PKCE, `state` (an ein Cookie gebunden, gegen Login-CSRF) und `nonce`.
Der Code wird **serverseitig** gegen die Tokens getauscht, das ID-Token wird per JWKS geprüft (Signatur, `iss`,
`aud`, `exp`, `nonce`). Danach hat der Browser nur ein eigenes Sitzungs-Cookie `mb_session` (HttpOnly, Secure).
Discovery und Tokentausch per Browser-`fetch` gibt es nicht – die `/oidc/config`- und `/oidc/token`-Durchreichungen
aus dem owa-gate-Vorschlag braucht die Magic Box also **nicht**.

### 1. Hydra-Client anlegen (auf hb-s-shieldy)

```bash
owagate client add magicbox "Magic Box" "https://magicbox.hackdv.com/auth/callback"
```

Das Geheimnis erscheint nur einmal. Hex-Geheimnis verwenden (`openssl rand -hex 32`), falls `owagate` dich wählen lässt
– die Magic Box kodiert zwar korrekt, aber Hex erspart Ärger mit `+` und `/`.

`form-action` in der CSP von owa-gate ergänzt sich automatisch aus den redirect_uris (Cache 5 Minuten, oder
`sudo systemctl restart owa-gate`).

### 2. Wie erreicht die Magic Box Hydra? (kein Hairpin-NAT!)

Der R640 erreicht `id.hackdv.com` über die öffentliche Adresse genauso wenig wie shieldy selbst. Zwei Möglichkeiten:

**a) Hosts-Eintrag auf dem R640 (empfohlen)** – `id.hackdv.com` zeigt auf die LAN-Adresse von shieldy, nginx dort
liefert Discovery, Token und JWKS mit gültigem Zertifikat:

```bash
echo "<LAN-IP-von-shieldy>  id.hackdv.com" | sudo tee -a /etc/hosts
```

Prüfen (alle drei müssen JSON liefern, nicht die Captcha-Seite):

```bash
curl -s https://id.hackdv.com/.well-known/openid-configuration | head -c 200; echo
```

```bash
curl -s https://id.hackdv.com/.well-known/jwks.json | head -c 120; echo
```

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://id.hackdv.com/oauth2/token   # erwartet 400/401, nicht 303
```

→ in der Konfiguration `oidc_internal_base` **leer** lassen.

**b) Hydra-Public-Port für den R640 öffnen** – Hydra lauscht dann auf der LAN-Adresse von shieldy, Firewall nur
für den R640 offen. → `"oidc_internal_base": "http://<LAN-IP-von-shieldy>:4444"`.
(Läuft die Magic Box doch auf shieldy selbst: `http://127.0.0.1:4444`.)

### 3. Konfiguration auf dem R640

`/etc/magicbox/settings.json` (nur die relevanten Schlüssel):

```json
{
  "auth_mode": "oidc",
  "public_url": "https://magicbox.hackdv.com",
  "oidc_issuer": "https://id.hackdv.com/",
  "oidc_internal_base": "",
  "oidc_client_id": "magicbox",
  "oidc_client_secret": "<GEHEIM aus Schritt 1>",
  "oidc_scopes": "openid email profile",
  "oidc_token_auth": "client_secret_basic",
  "auth_groups": ["magicbox"],
  "auth_allowed": [],
  "oidc_session_hours": 12,
  "web_token": ""
}
```

- `oidc_issuer` muss exakt dem `issuer` aus der Discovery entsprechen (Schrägstrich am Ende ist egal).
- `auth_groups`: Nur wer im Kratos-Trait `groups` den Eintrag `magicbox` hat, kommt rein (euer Consent-Handler
  schreibt `traits.groups` als `groups`-Claim ins ID-Token). Leer lassen = jeder mit gültigem Login.
- `auth_allowed`: zusätzlich oder alternativ E-Mails/Domains, z. B. `["@hackdv.com"]`.
- `oidc_token_auth`: Meldet der Tokentausch `invalid_client`, ist der Client in Hydra vermutlich auf
  `client_secret_post` eingestellt – dann diesen Wert eintragen.
- Fehlt nach dem Login der `groups`-Claim (Fehler „in keiner der Gruppen“), verlangt der Consent-Handler evtl. einen
  eigenen Scope → `"oidc_scopes": "openid email profile groups"`.
- `web_token` leer lassen, außer du willst die API aus Skripten nutzen (`Authorization: Bearer …`).

Die Magic Box darf nur von nginx auf shieldy erreichbar sein – auf dem R640:

```bash
sudo ufw allow from <LAN-IP-von-shieldy> to any port 8765 proto tcp
```

### 4. Gruppe `magicbox` vergeben (Kratos Admin API, auf shieldy)

Identität suchen:

```bash
curl -s "http://127.0.0.1:4434/admin/identities?credentials_identifier=yannick@hackdv.com" | python3 -m json.tool | grep -E '"id"|groups' -A3
```

Gruppe anhängen (wenn `traits.groups` schon existiert):

```bash
curl -s -X PATCH "http://127.0.0.1:4434/admin/identities/<ID>" -H "Content-Type: application/json" \
     -d '[{"op":"add","path":"/traits/groups/-","value":"magicbox"}]'
```

…bzw. falls die Identität noch gar keine Gruppen hat:

```bash
curl -s -X PATCH "http://127.0.0.1:4434/admin/identities/<ID>" -H "Content-Type: application/json" \
     -d '[{"op":"add","path":"/traits/groups","value":["magicbox"]}]'
```

Neue Gruppen wirken ab der nächsten Anmeldung (ID-Token wird beim Login ausgestellt).

### 5. nginx auf hb-s-shieldy

DNS: `magicbox.hackdv.com` → gleiche Adresse wie `id.hackdv.com`, Zertifikat per certbot.

`/etc/nginx/sites-available/magicbox.conf`:

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name magicbox.hackdv.com;

    ssl_certificate     /etc/letsencrypt/live/magicbox.hackdv.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/magicbox.hackdv.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 2g;          # Proben-Uploads
    proxy_request_buffering off;      # große Uploads direkt durchreichen

    # Live-Anzeige (Server-Sent Events): nicht puffern, lange offen lassen
    location = /api/events {
        proxy_pass http://<LAN-IP-R640>:8765;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }

    location / {
        proxy_pass http://<LAN-IP-R640>:8765;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/magicbox.conf /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload nginx
```

Kein `auth_request` nötig – die Magic Box prüft die Anmeldung selbst. Wer das Captcha-Gate trotzdem schon vor der
Magic-Box-Startseite will, kann `auth_request /_gate/challenge` wie bei `/kratos/` ergänzen (aber **nicht** für
`/auth/callback` und `/api/`).

### 6. Zugriff aus dem LAN (auch hier: kein Hairpin-NAT)

Browser und Desktop-App im LAN müssen `magicbox.hackdv.com` **und** `id.hackdv.com` (Login-Seiten) erreichen. Über
die öffentliche Adresse klappt das intern nicht. Lösung wie vermutlich schon für OWA: lokale DNS-Einträge (Router,
Pi-hole, AD-DNS) `magicbox.hackdv.com` und `id.hackdv.com` → LAN-IP von shieldy.

### 7. Desktop-App

*Magic Box → Server wechseln …* → `https://magicbox.hackdv.com`. Captcha, Kratos-Login und TOTP erscheinen im
App-Fenster; die Sitzung bleibt bis zu `oidc_session_hours` erhalten (auch über Neustarts des Servers).
„Abmelden“ oben rechts beendet die Magic-Box-Sitzung und die Hydra-Sitzung.

### Fehlersuche

| Symptom | Ursache / Lösung |
|---|---|
| „OIDC-Discovery … nicht erreichbar“ | R640 erreicht `id.hackdv.com` nicht → Schritt 2 (Hosts-Eintrag bzw. `oidc_internal_base`) |
| Ewiger Ladebalken nach dem Login, kein Fehler | CSP `form-action` von owa-gate kennt die Callback-Domain noch nicht → `systemctl restart owa-gate` |
| Hydra: `redirect_uri` stimmt nicht | Client-redirect_uri ≠ `public_url` + `/auth/callback` (auch http/https!) |
| „Token-Tausch fehlgeschlagen: invalid_client“ | Geheimnis falsch oder Client erwartet `client_secret_post` |
| „ID-Token ungültig: falscher Aussteller (iss)“ | `oidc_issuer` ≠ `issuer` aus der Discovery |
| „… ist in keiner der Gruppen magicbox“ | Gruppe fehlt (Schritt 4) oder `groups`-Scope nötig |
| „Ungültiger oder abgelaufener Anmeldevorgang (state)“ | Login dauerte > 10 Minuten, oder Cookie blockiert (Seite neu laden) |
| `the OAuth 2.0 Authorization request must be aborted` im Hydra-Log | normal, kein Fehler (interne Übergabe) |

Log: `journalctl -u magicbox-server -f`

**Abmelden-Ziel:** Hydra leitet nach dem Logout auf seine Standardseite. Soll es zurück zur Magic Box gehen, beim
Client `post_logout_redirect_uris` = `https://magicbox.hackdv.com/` registrieren und
`"oidc_post_logout_uri": "https://magicbox.hackdv.com/"` setzen (ohne Registrierung lehnt Hydra den Logout ab).

---

## Alternative: Kratos-Session direkt (`auth_mode: "kratos"`)

Nur sinnvoll, wenn Magic Box und Kratos dieselbe Cookie-Domain teilen.

```json
{
  "auth_mode": "kratos",
  "public_url": "https://magicbox.hackdv.com",
  "kratos_public_url": "http://<LAN-IP-von-shieldy>:4433",
  "kratos_browser_url": "https://id.hackdv.com/kratos",
  "auth_groups": ["magicbox"],
  "auth_require_aal2": true
}
```

Nötig in Kratos: `session.cookie.domain: hackdv.com` (beendet alle bestehenden Sitzungen) und
`selfservice.allowed_return_urls: [https://magicbox.hackdv.com/]`. `kratos_public_url` muss Kratos **direkt**
erreichen – der Weg über nginx `/kratos/` hängt am Captcha-`auth_request`.

## Alternative: Oathkeeper (`auth_mode: "oathkeeper"`)

Falls später Oathkeeper eingeführt wird: Magic Box hinter Oathkeeper, `cookie_session`-Authenticator und
`id_token`-Mutator (RS256), Magic Box prüft das Token über
`oathkeeper_jwks_url`, `oathkeeper_issuer`, `oathkeeper_audience`. Gruppen über einen `groups`-Claim im Mutator.
