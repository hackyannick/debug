import json
from pathlib import Path

import pytest

from magicbox.config import Settings
from magicbox.llm.client import LLMClient, LLMError
from magicbox.llm.documenter import facts_text, split_chunks
from magicbox.pipeline import run
from magicbox.report.builder import build_html, markdown_to_html
from samples import tiny_pe64


def test_ollama_chat_streams_and_strips_think(fake_llm):
    s = Settings(base_url=fake_llm.url, context_tokens=8192)
    tokens = []
    out = LLMClient(s).chat([{"role": "user", "content": "hi"}], on_token=tokens.append)
    assert out.startswith("## Kurzfassung")
    assert "<think>" not in out and "".join(tokens).startswith("<think>")
    req = fake_llm.requests[-1]
    assert req["path"] == "/api/chat"
    assert req["options"]["num_ctx"] == 8192  # wichtig: sonst schneidet Ollama still bei 2–4k Tokens ab


def test_openai_compatible(fake_llm):
    s = Settings(base_url=fake_llm.url, provider="openai")
    assert LLMClient(s).list_models() == ["qwen2.5-coder:7b"]
    out = LLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert "Einstufung: unbedenklich" in out
    assert fake_llm.requests[-1]["path"] == "/v1/chat/completions"


def test_check_reports_missing_model(fake_llm):
    s = Settings(base_url=fake_llm.url, model="gibtsnicht:1b")
    with pytest.raises(LLMError, match="ollama pull gibtsnicht:1b"):
        LLMClient(s).check()
    assert "bereit" in LLMClient(Settings(base_url=fake_llm.url)).check()


def test_unreachable_server():
    s = Settings(base_url="http://127.0.0.1:9", timeout_s=2)
    with pytest.raises(LLMError, match="nicht erreichbar"):
        LLMClient(s).list_models()


def test_split_chunks_respects_size():
    text = "\n".join(f"line {i} " + "x" * 50 for i in range(200))
    chunks = split_chunks(text, 1000)
    assert all(len(c) <= 1000 for c in chunks)
    assert "".join(chunks) == text


def test_pipeline_end_to_end(fake_llm, tmp_path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(tiny_pe64())
    s = Settings(base_url=fake_llm.url, output_dir=str(tmp_path / "out"), use_radare2=False)
    outcome = run(exe, s)
    md = outcome.files.markdown.read_text(encoding="utf-8")
    assert "## Kurzfassung" in md and "Technischer Anhang" in md
    assert outcome.llm_error == ""
    prompt = fake_llm.requests[-1]["messages"][1]["content"]
    assert "WS2_32.dll" in prompt and "Netzwerk" in prompt
    data = json.loads(outcome.files.json.read_text(encoding="utf-8"))
    assert data["kind"] == "pe" and data["llm_doc"]
    html = outcome.files.html.read_text(encoding="utf-8")
    assert "&lt;b&gt;Test&lt;/b&gt;" in html  # LLM-HTML wird nicht roh übernommen


def test_pipeline_without_llm_server(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("print('hallo')\n")
    s = Settings(base_url="http://127.0.0.1:9", output_dir=str(tmp_path / "out"), timeout_s=2)
    outcome = run(f, s)
    assert "nicht erreichbar" in outcome.llm_error
    assert "KI-Dokumentation nicht verfügbar" in outcome.files.markdown.read_text(encoding="utf-8")


def test_large_code_is_chunked(fake_llm, tmp_path):
    f = tmp_path / "big.py"
    f.write_text("\n".join(f"def f{i}(x):\n    return x + {i}\n" for i in range(1500)))
    s = Settings(base_url=fake_llm.url, output_dir=str(tmp_path / "out"), context_tokens=4096, max_code_chunks=3)
    run(f, s)
    labels = [r["messages"][1]["content"][:60] for r in fake_llm.requests]
    assert len(fake_llm.requests) == 4  # 3 Code-Teile + finale Doku
    assert all(len(r["messages"][1]["content"]) < s.context_chars * 1.2 for r in fake_llm.requests), labels


def test_facts_budget():
    from magicbox.engine import Engine
    r = Engine(Settings(use_radare2=False)).analyze_bytes("t.exe", tiny_pe64())
    text = facts_text(r, 2000)
    assert len(text) < 2600 and "PE-Header" in text


def test_html_sanitizing():
    out = markdown_to_html("<script>alert(1)</script> [x](javascript:alert(1)) ![p](http://tracker/x.png)")
    assert "<script>" not in out and "javascript:" not in out and "tracker" not in out
    assert "Content-Security-Policy" in build_html("# t", "t")
