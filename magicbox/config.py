"""Einstellungen (persistiert als JSON im Benutzerprofil)."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, fields
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

    # Analyse
    output_dir: str = ""
    max_archive_depth: int = 3
    max_archive_members: int = 200
    max_extract_bytes: int = 512 * 1024 * 1024
    max_disasm_functions: int = 12
    use_radare2: bool = True
    radare2_path: str = "r2"

    def __post_init__(self) -> None:
        if not self.output_dir:
            self.output_dir = default_output_dir()

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
        path = path or config_dir() / "settings.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in known})

    def save(self, path: Path | None = None) -> Path:
        path = path or config_dir() / "settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
        return path
