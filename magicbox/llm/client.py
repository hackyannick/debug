"""Minimaler LLM-Client für Ollama und OpenAI-kompatible Server (llama.cpp, vLLM, LM Studio, LocalAI …).

Bewusst nur mit der Standardbibliothek umgesetzt, damit nichts Zusätzliches installiert werden muss.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Callable, Iterator

from magicbox.config import Settings
from magicbox.llm.tidy import loop_start

THINK_RE = re.compile(r"<think>.*?</think>\s*", re.S)


class LLMError(RuntimeError):
    pass


class LLMCancelled(LLMError):
    pass


class LLMClient:
    def __init__(self, settings: Settings, is_cancelled: Callable[[], bool] | None = None):
        self.s = settings
        self.is_cancelled = is_cancelled or (lambda: False)

    # ------------------------------------------------------------------ helpers
    @property
    def base(self) -> str:
        url = self.s.base_url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        if self.s.provider == "openai" and not url.endswith("/v1"):
            url += "/v1"
        return url

    def _request(self, path: str, payload: dict | None = None, timeout: float | None = None):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.s.api_key:
            headers["Authorization"] = f"Bearer {self.s.api_key}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
        try:
            return urllib.request.urlopen(req, timeout=timeout or self.s.timeout_s)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")[:500]
            raise LLMError(f"HTTP {exc.code} von {self.base}{path}: {body}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise LLMError(f"Server {self.base} nicht erreichbar: {reason}") from exc

    # ------------------------------------------------------------------ API
    def list_models(self) -> list[str]:
        if self.s.provider == "ollama":
            with self._request("/api/tags", timeout=10) as r:
                return sorted(m["name"] for m in json.load(r).get("models", []))
        with self._request("/models", timeout=10) as r:
            return sorted(m["id"] for m in json.load(r).get("data", []))

    def check(self) -> str:
        """Prüft Verbindung + ob das Modell vorhanden ist. Gibt eine lesbare Statusmeldung zurück."""
        models = self.list_models()
        if self.s.model in models or (self.s.provider == "ollama" and f"{self.s.model}:latest" in models):
            return f"Verbunden mit {self.base} – Modell „{self.s.model}“ bereit."
        hint = f" Auf dem Server ausführen: ollama pull {self.s.model}" if self.s.provider == "ollama" else ""
        avail = ", ".join(models[:10]) or "keine"
        raise LLMError(f"Server erreichbar, aber Modell „{self.s.model}“ fehlt.{hint} Verfügbar: {avail}")

    def chat(self, messages: list[dict], on_token: Callable[[str], None] | None = None) -> str:
        parts: list[str] = []
        stream = self._stream(messages)
        try:
            for token in stream:
                if self.is_cancelled():
                    raise LLMCancelled("Abgebrochen")
                parts.append(token)
                if on_token:
                    on_token(token)
                # Wiederholungsschleife: Generierung abbrechen statt bis zum Token-Limit weiterzurechnen
                if "\n" in token and loop_start("".join(parts)) is not None:
                    if on_token:
                        on_token("\n[Wiederholung erkannt – Antwort hier abgeschnitten]\n")
                    break
        finally:
            stream.close()  # beendet die HTTP-Verbindung, Ollama stoppt dann die Generierung
        text = THINK_RE.sub("", "".join(parts))
        pos = loop_start(text)
        return (text[:pos] if pos is not None else text).strip()

    def _stream(self, messages: list[dict]) -> Iterator[str]:
        s = self.s
        if s.provider == "ollama":
            payload = {
                "model": s.model, "messages": messages, "stream": True,
                "options": {"temperature": s.temperature, "num_ctx": s.context_tokens,
                            "num_predict": s.answer_tokens},
            }
            with self._request("/api/chat", payload) as r:
                for raw in r:
                    line = raw.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    if obj.get("error"):
                        raise LLMError(obj["error"])
                    yield obj.get("message", {}).get("content", "")
                    if obj.get("done"):
                        return
        else:
            payload = {"model": s.model, "messages": messages, "stream": True,
                       "temperature": s.temperature, "max_tokens": s.answer_tokens}
            with self._request("/chat/completions", payload) as r:
                for raw in r:
                    line = raw.decode(errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        return
                    obj = json.loads(data)
                    if obj.get("error"):
                        raise LLMError(str(obj["error"]))
                    for choice in obj.get("choices", []):
                        delta = choice.get("delta") or {}
                        yield delta.get("content") or ""
