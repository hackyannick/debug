import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
# Fake-LLM läuft lokal – niemals über einen Proxy gehen
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

from magicbox.config import Settings  # noqa: E402


@pytest.fixture
def settings(tmp_path):
    return Settings(output_dir=str(tmp_path / "reports"), use_llm=False, use_radare2=False)


@pytest.fixture
def fake_llm():
    from fake_llm import FakeLLM

    server = FakeLLM()
    yield server
    server.close()
