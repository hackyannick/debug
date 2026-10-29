# Anmeldung über deinen Ory-Stack

Die Magic Box kann die Anmeldung komplett an Ory abgeben – dann gilt für sie derselbe Login wie für deine anderen
Dienste, inklusive Captcha, Passwort-Regeln und zweitem Faktor, so wie es in Kratos bzw. deinem Login-UI eingerichtet
ist. Die Magic Box selbst kennt keine Passwörter.

Zwei Varianten – nimm die, die zu deinem Aufbau passt:

| | **A: Kratos direkt** | **B: Oathkeeper davor** |
|---|---|---|
| Wer prüft die Sitzung? | Magic Box fragt Kratos (`/sessions/whoami`) | Oathkeeper (z. B. `cookie_session` → Kratos) |
| Was bekommt die Magic Box? | Das Kratos-Session-Cookie | Ein von Oathkeeper signiertes ID-Token (JWT) |
| Voraussetzung | Magic Box liegt unter derselben (Eltern-)Domain wie Kratos, damit das Cookie mitgeschickt wird | Magic Box ist **nur** über Oathkeeper erreichbar (lauscht auf `127.0.0.1`) |
| Passt gut, wenn … | du Kratos + Login-UI ohne Proxy nutzt | du schon Oathkeeper vor anderen Diensten (z. B. OWA) einsetzt |

Die Einstellungen stehen in `/etc/magicbox/settings.json` (absichtlich **nicht** in der Web-Oberfläche änderbar).
Danach: `sudo systemctl restart magicbox-server`.

## Gemeinsame Einstellungen

| Schlüssel | Bedeutung |
|---|---|
| `auth_mode` | `"kratos"` oder `"oathkeeper"` (Standard `"token"` = Zugangsschlüssel) |
| `public_url` | Externe Adresse der Magic Box, z. B. `https://magicbox.firma.de` – Rücksprungziel nach dem Login |
| `auth_allowed` | Wer darf rein? Liste aus E-Mails oder Domains: `["@firma.de", "extern@partner.de"]`. Leer = jede gültige Sitzung |
| `auth_require_aal2` | `true` = nur Sitzungen mit zweitem Faktor (Kratos AAL2); sonst Weiterleitung zum 2FA-Schritt |
| `auth_login_url` | Optional: eigene Login-Seite statt `…/self-service/login/browser` |
| `web_token` | Bleibt zusätzlich gültig für Skripte/CLI (`Authorization: Bearer …`) – leer lassen, wenn nicht gebraucht |

Wer einen Auftrag hochgeladen hat, steht danach am Auftrag („von analyst@firma.de“).

## Variante A: Kratos direkt

```json
{
  "auth_mode": "kratos",
  "public_url": "https://magicbox.firma.de",
  "kratos_public_url": "http://127.0.0.1:4433",
  "kratos_browser_url": "https://auth.firma.de",
  "auth_allowed": ["@firma.de"],
  "auth_require_aal2": true
}
```

- `kratos_public_url`: Kratos **Public API**, wie die Magic Box sie erreicht (intern, kein Proxy nötig).
- `kratos_browser_url`: dieselbe Public API aus Sicht des Browsers (das, was in Kratos als `serve.public.base_url` steht).

Ablauf: Ohne gültige Sitzung leitet die Magic Box zu
`https://auth.firma.de/self-service/login/browser?return_to=https://magicbox.firma.de/` – Kratos schickt den Browser
zu deinem Login-UI (mit Captcha), nach dem Login kommt er zurück. „Abmelden“ oben rechts startet den Kratos-Logout.

**In der Kratos-Konfiguration nötig:**

```yaml
selfservice:
  allowed_return_urls:
    - https://magicbox.firma.de/      # sonst lehnt Kratos den Rücksprung ab

session:
  cookie:
    domain: firma.de                  # Cookie auch an magicbox.firma.de schicken
    same_site: Lax
```

Wenn Kratos und Magic Box unter verschiedenen Domains laufen (z. B. `auth.example.de` und `magicbox.lan`), sieht die
Magic Box das Cookie nicht → dann Variante B verwenden.

## Variante B: Oathkeeper davor

```json
{
  "auth_mode": "oathkeeper",
  "public_url": "https://magicbox.firma.de",
  "oathkeeper_jwks_url": "http://127.0.0.1:4456/.well-known/jwks.json",
  "oathkeeper_issuer": "https://auth.firma.de/",
  "oathkeeper_audience": "magicbox",
  "kratos_public_url": "http://127.0.0.1:4433",
  "kratos_browser_url": "https://auth.firma.de",
  "auth_allowed": ["@firma.de"]
}
```

`kratos_*` ist hier optional und wird nur für „Abmelden“ und den 2FA-Rücksprung genutzt. Die Magic Box muss auf
`127.0.0.1` lauschen, damit niemand an Oathkeeper vorbei kommt – im Dienst also `--host 127.0.0.1` statt `0.0.0.0`
(`/etc/systemd/system/magicbox-server.service`).

Die Magic Box akzeptiert ID-Tokens mit **RS256/RS384/RS512** (Oathkeeper-Standard bei RSA-Schlüsseln) und prüft
Signatur, `exp`/`nbf`, `iss`, `aud`. Neue Schlüssel (Rotation) werden automatisch nachgeladen.

**Access Rule für Oathkeeper** (Beispiel, an deine Rules anpassen):

```yaml
- id: magicbox
  upstream:
    url: http://127.0.0.1:8765
    preserve_host: true
  match:
    url: https://magicbox.firma.de/<**>
    methods: [GET, POST, PUT, DELETE, HEAD]
  authenticators:
    - handler: cookie_session        # prüft die Kratos-Sitzung – wie bei deinen anderen Diensten
  authorizer:
    handler: allow
  mutators:
    - handler: id_token
      config:
        claims: |
          {
            "aud": ["magicbox"],
            "email": "{{ print .Extra.identity.traits.email }}",
            "aal": "{{ print .Extra.authenticator_assurance_level }}"
          }
  errors:
    - handler: redirect
      config:
        to: https://auth.firma.de/self-service/login/browser?return_to=https://magicbox.firma.de/
        when:
          - error: [unauthorized, forbidden]
            request:
              header:
                accept: [text/html]
    - handler: json                   # API-Aufrufe der Oberfläche bekommen 401 statt einer HTML-Weiterleitung
```

Und in `oathkeeper.yml` den `id_token`-Mutator aktivieren (falls noch nicht):

```yaml
mutators:
  id_token:
    enabled: true
    config:
      issuer_url: https://auth.firma.de/
      jwks_url: file:///etc/oathkeeper/id_token.jwks.json   # RSA-Schlüssel, z. B. "oathkeeper credentials generate --alg RS256"
      ttl: 60s
```

Die Magic Box liest die öffentlichen Schlüssel über Oathkeepers API (`/.well-known/jwks.json`, Port 4456).

**Hinweise:**
- Live-Anzeige (KI schreibt mit) nutzt Server-Sent Events – Oathkeeper reicht die ohne Zwischenspeichern durch.
  Falls doch ein weiterer Proxy (nginx, Traefik) davor sitzt: Pufferung für `/api/events` abschalten
  (`proxy_buffering off;`).
- Upload-Größe: Oathkeeper begrenzt nicht, ein vorgeschalteter nginx ggf. schon (`client_max_body_size 2g;`).

## Desktop-App

Die Desktop-App zeigt den Ory-Login (inkl. Captcha) direkt im App-Fenster an und merkt sich die Sitzung.
Server eintragen über *Magic Box → Server wechseln …* → `https://magicbox.firma.de`.

## Fehlersuche

| Symptom | Ursache |
|---|---|
| Endlosschleife Login → Magic Box → Login | Cookie kommt nicht an (Variante A: `session.cookie.domain`), oder `kratos_public_url` falsch |
| Kratos meldet „return_to not allowed“ | `selfservice.allowed_return_urls` ergänzen |
| 403 „ist nicht freigeschaltet“ | E-Mail/Domain fehlt in `auth_allowed` |
| 401 „ID-Token ungültig: falsche Zielgruppe“ | `aud` im Oathkeeper-Mutator ≠ `oathkeeper_audience` |
| 401 „unbekannter Schlüssel (kid)“ | `oathkeeper_jwks_url` zeigt nicht auf Oathkeepers API bzw. Schlüssel nicht RSA |

Log: `journalctl -u magicbox-server -f`
