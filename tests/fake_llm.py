"""Ein winziger Fake-LLM-Server (Ollama- und OpenAI-Protokoll) für Tests – ohne echtes Modell."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ANSWER = "## Kurzfassung\nDas ist ein <b>Test</b>-Programm.\n\n## Sicherheitsbewertung\nEinstufung: unbedenklich"


class FakeLLM:
    def __init__(self, answer: str = ANSWER, models=("qwen2.5-coder:7b",)):
        self.answer = answer
        self.models = list(models)
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, obj, code=200):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/api/tags":
                    self._json({"models": [{"name": m} for m in outer.models]})
                elif self.path == "/v1/models":
                    self._json({"data": [{"id": m} for m in outer.models]})
                else:
                    self._json({"error": "not found"}, 404)

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, **payload})
                words = ("<think>hmm</think>" + outer.answer).split(" ")
                self.send_response(200)
                self.end_headers()
                if self.path == "/api/chat":
                    for i, w in enumerate(words):
                        chunk = w + (" " if i < len(words) - 1 else "")
                        self.wfile.write(json.dumps({"message": {"content": chunk}, "done": False}).encode() + b"\n")
                    self.wfile.write(json.dumps({"message": {"content": ""}, "done": True}).encode() + b"\n")
                else:
                    for i, w in enumerate(words):
                        chunk = w + (" " if i < len(words) - 1 else "")
                        self.wfile.write(b"data: " + json.dumps({"choices": [{"delta": {"content": chunk}}]}).encode() + b"\n\n")
                    self.wfile.write(b"data: [DONE]\n\n")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
