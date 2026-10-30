"""KI-Nachbearbeitung: Wiederholungsschleifen abbrechen, Glossar auf verwendete Begriffe kürzen."""

from magicbox.config import Settings
from magicbox.llm.client import LLMClient
from magicbox.llm.tidy import loop_start, tidy_glossary

LOOP = "\n".join(f"| Audio-Stream-Format-Qualität-{w} | Ein {w} für Audiostream-Formate |"
                 for w in ["Codec", "Player", "Renderer", "Device", "Output", "Input", "Buffer", "Callback", "Event",
                           "Status", "Fehler", "Verbindung", "Codec-Player", "Codec-Renderer", "Codec-Device",
                           "Codec-Output", "Codec-Input", "Codec-Buffer"] * 3)


def test_loop_is_detected_but_normal_lists_and_code_are_not():
    text = "## Glossar\n| Begriff | Erklärung |\n|---|---|\n| Electron | Framework |\n" + LOOP
    pos = loop_start(text)
    assert pos is not None and text[:pos].endswith("| Electron | Framework |\n| Audio-Stream-Format-Qualität-Codec "
                                                    "| Ein Codec für Audiostream-Formate |")
    channels = "\n".join(f"- `request-localMusic-{c}`" for c in ("albums", "artists", "tracks", "trackIds", "remove"))
    assert loop_start(channels) is None
    code = "```\n" + "\n".join(f"mov dword [rsp + 0x{i:02x}], 0x00000000 ; local_{i}" for i in range(40)) + "\n```"
    assert loop_start(code) is None


def test_glossary_keeps_only_terms_used_in_the_text():
    doc = ("## Kurzfassung\nQobuz nutzt Electron und IPC sowie Chromecast.\n\n## Glossar\n"
           "| Begriff | Erklärung |\n|---|---|\n| Electron | Framework |\n| IPC (Inter-Process Communication) | Kanäle |\n"
           "| Electron | doppelt |\n| Audio-Stream-Codec | erfunden |\n| `Chromecast` | Google-Dienst |\n\nNachsatz")
    out = tidy_glossary(doc)
    assert "| Electron | Framework |" in out and "| IPC (Inter-Process Communication) | Kanäle |" in out
    assert "doppelt" not in out and "Audio-Stream-Codec" not in out and "| `Chromecast` |" in out
    assert out.startswith("## Kurzfassung") and out.endswith("Nachsatz")


def test_streaming_stops_at_a_loop(fake_llm):
    fake_llm.answer = "## Glossar\n| Electron | Framework |\n" + LOOP + "\n" + LOOP
    tokens: list[str] = []
    out = LLMClient(Settings(base_url=fake_llm.url)).chat([{"role": "user", "content": "x"}], on_token=tokens.append)
    assert out.endswith("| Audio-Stream-Format-Qualität-Codec | Ein Codec für Audiostream-Formate |")
    assert any("Wiederholung erkannt" in t for t in tokens)
    assert sum(t.count("\n") for t in tokens) < LOOP.count("\n")  # nicht bis zum Ende mitgelesen


def test_bundle_map_drops_library_messages_env_and_bad_imports():
    from magicbox.analyzers.jsbundle import extract
    from magicbox.analyzers.source import MODULE_NAME_RE
    text = ('a="Corrupted zip: can\'t find end of central directory";b="No client configured on scope - will not '
            'capture event!";c="Attempted to set both pressDelay and distance on SortableContainer";'
            'd="Slow access to the selected disk could degrade your user experience.";'
            'process.env.SENTRY_DSN;process.env.GITHUB_SHA;process.env.QOBUZ_ENV;') * 3
    facts = extract(text, {"qobuz"})
    assert facts["texts"] == ["Slow access to the selected disk could degrade your user experience."]
    assert facts["env"] == ["QOBUZ_ENV"]
    assert not MODULE_NAME_RE.match("%s, +l),s.warn(") and MODULE_NAME_RE.match("@qobuz/qobuz-dwp-ui")


def test_lottie_animations_are_not_sent_to_the_llm():
    from magicbox.llm.documenter import ANIMATION_DATA_RE
    assert ANIMATION_DATA_RE.search("app/node_modules/@qobuz/qobuz-dwp-ui/dist/assets/motions/lotties/sound_visualizer.json")
    assert not ANIMATION_DATA_RE.search("app/package.json")
