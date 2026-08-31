"""Reteaua e blocata implicit in teste (pytest-socket, vezi addopts din pyproject).

Un test care incearca sa atinga infrastructura atacatorului esueaza automat.
Testele care au voie sa vorbeasca cu Ollama pe loopback folosesc marker-ul
@pytest.mark.needs_ollama.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_socket import enable_socket, socket_allow_hosts  # type: ignore[import-untyped]

CORPUS = Path(__file__).parent.parent / "corpus" / "eml"


@pytest.fixture(autouse=True)
def _allow_ollama_only_when_marked(request: pytest.FixtureRequest) -> None:
    if request.node.get_closest_marker("needs_ollama"):
        enable_socket()
        socket_allow_hosts(["127.0.0.1", "localhost", "::1"], allow_unix_socket=True)


@pytest.fixture
def corpus_dir() -> Path:
    return CORPUS
