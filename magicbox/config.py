"""Einstellungen (persistiert als JSON im Benutzerprofil)."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path


def config_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "magicbox"


def default_output_dir() -> str:
    return str(Path.home() / "MagicBox" / "Berichte")


def default_data_dir() -> str:
    return str(Path.home() / "MagicBox" / "Daten")


def install_defaults() -> dict:
    """Vorgaben des Installers (z. B. Server-Adresse) aus ``magicbox-defaults.json`` neben der Programmdatei."""
    candidates = []
    if os.environ.get("MAGICBOX_DEFAULTS"):
        candidates.append(Path(os.environ["MAGICBOX_DEFAULTS"]))
    if getattr(sys, "frozen", False):  # PyInstaller-Build
        candidates.append(Path(sys.executable).resolve().parent / "magicbox-defaults.json")
    for c in candidates:
        try:
            data = json.loads(c.read_text(encoding="utf-8-sig"))  # Inno Setup schreibt ggf. mit BOM
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            continue
    return {}


@dataclass
class Settings:
    # LLM
    use_llm: bool = True
    provider: str = "ollama"  # "ollama" | "openai" (OpenAI-kompatibel: llama.cpp, vLLM, LM Studio …)
    base_url: str = "http://r640:11434"
    model: str = "qwen2.5-coder:7b"
    api_key: str = ""
    context_tokens: int = 16384
    max_answer_tokens: int = 3072
    temperature: float = 0.2
    timeout_s: int = 1800
    language: str = "Deutsch"
    audience: str = "verständlich für technisch interessierte Laien"
    max_llm_children: int = 12  # max. Einzel-Zusammenfassungen bei Archiven/Ordnern
    max_code_chunks: int = 6  # max. Code-Teilstücke, die einzeln vom LLM gelesen werden

    # Berichtsprofil: "malware" (IOCs, ATT&CK, Erkennung) oder "allgemein" (Software-Doku)
    profile: str = "malware"

    # Analyse
    output_dir: str = ""
    max_archive_depth: int = 3
    max_archive_members: int = 200
    max_extract_bytes: int = 512 * 1024 * 1024
    max_disasm_functions: int = 12
    use_radare2: bool = True
    radare2_path: str = "r2"

    # Malware-Suite (externe Werkzeuge sind optional – fehlen sie, wird der Schritt übersprungen)
    archive_passwords: list[str] = field(default_factory=lambda: ["infected", "malware", "virus", "password"])
    upx_path: str = "upx"
    sevenzip_path: str = "7z"
    use_capa: bool = True
    capa_path: str = "capa"
    capa_rules: str = ""  # Ordner mit capa-Regeln (bei der Standalone-capa-Binary nicht nötig)
    capa_timeout_s: int = 900
    yara_rules_dir: str = ""  # zusätzliche eigene/Community-Regeln; mitgelieferte Regeln laufen immer
    ilspy_path: str = "ilspycmd"
    tool_timeout_s: int = 300

    # Server / Web-Oberfläche
    data_dir: str = ""
    host: str = "127.0.0.1"
    port: int = 8765
    web_token: str = ""  # wenn gesetzt, verlangt die Web-Oberfläche diesen Zugangsschlüssel (auch für Skripte/API)

    # Anmeldung: "token" (Zugangsschlüssel) | "oidc" (z. B. Ory Hydra) | "kratos" (Kratos-Session)
    #            | "oathkeeper" (Oathkeeper-ID-Token)
    auth_mode: str = "token"
    public_url: str = ""  # externe Adresse der Magic Box (für Rücksprung nach dem Login), z. B. https://magicbox.example.de
    kratos_public_url: str = ""  # Kratos Public API, von der Magic Box aus erreichbar, z. B. http://127.0.0.1:4433
    kratos_browser_url: str = ""  # Kratos Public API aus Sicht des Browsers (leer = kratos_public_url)
    oathkeeper_jwks_url: str = ""  # z. B. http://127.0.0.1:4456/.well-known/jwks.json
    oathkeeper_issuer: str = ""  # erwarteter "iss" im ID-Token (leer = nicht prüfen)
    oathkeeper_audience: str = ""  # erwartetes "aud" im ID-Token (leer = nicht prüfen)
    auth_login_url: str = ""  # optional: eigene Login-Seite statt des Kratos-Browser-Flows
    auth_allowed: list[str] = field(default_factory=list)  # E-Mails oder "@domain"; leer = alle Angemeldeten
    auth_groups: list[str] = field(default_factory=list)  # erlaubte Gruppen (Claim/Trait "groups"); leer = egal
    # OIDC (Authorization Code + PKCE), z. B. gegen Ory Hydra
    oidc_issuer: str = ""  # öffentlicher Aussteller, z. B. https://id.hackdv.com/
    oidc_internal_base: str = ""  # Discovery/Token/JWKS intern abrufen, z. B. http://127.0.0.1:4444 (kein Hairpin-NAT)
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid email profile"
    oidc_token_auth: str = "client_secret_basic"  # oder "client_secret_post"
    oidc_post_logout_uri: str = ""  # nur setzen, wenn beim Client als post_logout_redirect_uri registriert
    oidc_session_hours: int = 12
    auth_require_aal2: bool = False  # nur Sitzungen mit zweitem Faktor (Kratos AAL2) zulassen
    max_upload_mb: int = 2048

    # Desktop-App: leer = eingebauter lokaler Server, sonst z. B. http://r640:8765
    server_url: str = ""

    def __post_init__(self) -> None:
        if not self.output_dir:
            self.output_dir = default_output_dir()
        if not self.data_dir:
            self.data_dir = default_data_dir()

    @property
    def answer_tokens(self) -> int:
        """Für die Antwort reservierte Tokens (höchstens ein Drittel des Kontexts)."""
        return max(256, min(self.max_answer_tokens, self.context_tokens // 3))

    @property
    def context_chars(self) -> int:
        """Grobe Zeichen-Budgetierung für den Prompt (≈3 Zeichen pro Token bei Code)."""
        usable = max(1024, self.context_tokens - self.answer_tokens - 600)
        return usable * 3

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        """Lädt die Benutzereinstellungen; gibt es noch keine, gelten die Vorgaben aus der Installation."""
        known = {f.name for f in fields(cls)}
        path = path or config_dir() / "settings.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = install_defaults()
        return cls(**{k: v for k, v in raw.items() if k in known})

    def save(self, path: Path | None = None) -> Path:
        path = path or config_dir() / "settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
        return path
