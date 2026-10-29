"""Eigene Fragen an die KI: beim Hochladen und als Nachfrage zu fertigen Aufträgen."""

import json

from magicbox.config import Settings
from magicbox.llm.documenter import code_units, parse_terms, question_terms, select_units
from magicbox.model import AnalysisResult, Section, Table
from magicbox.pipeline import ask, run
from test_server import request, server, wait_done  # noqa: F401 – Fixture wird wiederverwendet
from samples import tiny_pe64

PSEUDO = ("// ===== main@0x401000 =====\nint main() { init(); beacon(); }\n\n"
          "// ===== fcn.beacon@0x401200 =====\nvoid beacon() { s = socket(); connect(s, \"10.0.0.1\"); send(s, buf); }\n\n"
          "// ===== fcn.crypt@0x401400 =====\nvoid enc(char *b) { for (i...) b[i] ^= key[i % 16]; CryptEncrypt(h, b); }\n")


def sample_result() -> AnalysisResult:
    r = AnalysisResult("/x/evil.exe", "evil.exe", 1234, kind="pe", description="PE64")
    r.add(Section("Funktionen", table=Table(["Name", "Adresse"], [["main", "0x401000"]]), llm_priority=2))
    r.add(Section("Pseudocode (radare2 pdc)", code=PSEUDO, code_lang="c", llm_priority=2))
    r.add(Section("C#", code_lang="csharp", code=(
        "namespace A {\n  public class Net {\n    public void Upload(string s) {\n      http.Post(s);\n    }\n"
        "    private static byte[] Decrypt(byte[] d) {\n      return Aes.Create().Decrypt(d);\n    }\n  }\n}\n")))
    return r


def test_code_units_split_per_function():
    labels = [u[0] for u in code_units(sample_result())]
    assert labels[:3] == ["main@0x401000", "fcn.beacon@0x401200", "fcn.crypt@0x401400"]
    assert any(l.startswith("public void Upload") for l in labels)
    assert any(l.startswith("private static byte[] Decrypt") for l in labels)


def test_terms_and_selection():
    assert question_terms("Suche mir bitte die Funktion, die Daten verschlüsselt") == ["daten", "verschlüsselt"]
    assert parse_terms("crypt, AES, `xor`\n- CryptEncrypt") == ["crypt", "aes", "xor", "cryptencrypt"]
    picked = [u[0] for u in select_units(code_units(sample_result()), ["crypt", "xor", "aes"], 100000)]
    assert set(picked[:2]) == {"fcn.crypt@0x401400", "private static byte[] Decrypt(byte[] d) {"}
    assert "main@0x401000" not in picked


def test_from_dict_roundtrip():
    r = sample_result()
    r.find("high", "Böse", "x")
    r.children.append(AnalysisResult("/x/a", "a.txt", 3))
    r.qa.append({"question": "q", "answer": "a"})
    back = AnalysisResult.from_dict(json.loads(json.dumps(r.to_dict())))
    assert back.to_dict() == r.to_dict()


def test_ask_searches_code_when_it_does_not_fit(fake_llm, tmp_path):
    r = sample_result()
    r.add(Section("Füllcode", code="\n".join(f"int filler{i}() {{ return {i}; }}" for i in range(3000)), code_lang="c"))
    fake_llm.answer = "crypt, xor, CryptEncrypt"
    s = Settings(base_url=fake_llm.url, output_dir=str(tmp_path), context_tokens=4096)
    outcome = ask(r, "Welche Funktion verschlüsselt die Daten? Erkläre sie verständlich.", s,
                  report_folder=tmp_path / "rep")
    assert len(fake_llm.requests) == 2  # Suchbegriffe + Antwort
    final = fake_llm.requests[-1]["messages"][1]["content"]
    assert "fcn.crypt@0x401400" in final and "Auszug" in final and "filler2999" not in final
    assert len(final) < s.context_chars * 1.2
    md = outcome.files.markdown.read_text(encoding="utf-8")
    assert "Deine Fragen an die KI" in md and "Welche Funktion verschlüsselt" in md
    assert json.loads(outcome.files.json.read_text(encoding="utf-8"))["qa"][0]["answer"]


def test_question_with_upload_pipeline(fake_llm, tmp_path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(tiny_pe64())
    s = Settings(base_url=fake_llm.url, output_dir=str(tmp_path / "out"), use_radare2=False, use_capa=False)
    outcome = run(exe, s, question="Was macht main?")
    assert outcome.result.qa and outcome.result.llm_doc
    assert "# Frage\nWas macht main?" in fake_llm.requests[0]["messages"][1]["content"]
    md = outcome.files.markdown.read_text(encoding="utf-8")
    assert md.index("Deine Fragen") < md.index("Auf einen Blick")


def test_server_question_and_followup(server):  # noqa: F811
    status, job, _ = request(server, "POST", "/api/jobs?name=evil.exe&question=Was%20macht%20main%3F", body=tiny_pe64())
    assert status == 201 and job["question"] == "Was macht main?"
    job = wait_done(server, job["id"])
    assert job["status"] == "done" and job["qa_count"] == 1
    first_ai = job["ai"]

    status, err, _ = request(server, "POST", f"/api/jobs/{job['id']}/ask", body={"question": "  "})
    assert status == 400
    status, queued, _ = request(server, "POST", f"/api/jobs/{job['id']}/ask", body={"question": "Gibt es Netzwerkcode?"})
    assert status == 200 and queued["status"] == "queued" and queued["ask"]
    job = wait_done(server, job["id"])
    assert job["status"] == "done" and job["qa_count"] == 2 and not job["ask"] and not job["notice"]
    assert job["ai"].startswith(first_ai) and len(job["ai"]) > len(first_ai)  # KI-Text wird fortgesetzt
    assert job["risk"] and job["llm_verdict"]  # Ergebnis der Analyse bleibt erhalten
    _, html, _ = request(server, "GET", f"/api/jobs/{job['id']}/report")
    assert b"Gibt es Netzwerkcode?" in html and b"Was macht main?" in html
