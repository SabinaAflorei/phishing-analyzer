"""Reteaua e blocata implicit in teste (pytest-socket, vezi addopts din pyproject).

Un test care incearca sa atinga infrastructura atacatorului esueaza automat.
Testele care au voie sa vorbeasca cu Ollama pe loopback folosesc marker-ul
@pytest.mark.needs_ollama.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_socket import enable_socket, socket_allow_hosts  # type: ignore[import-untyped]

from triage import db

CORPUS = Path(__file__).parent.parent / "corpus" / "eml"


_LOOPBACK = ["127.0.0.1", "localhost", "::1"]


@pytest.fixture(autouse=True)
def _allow_ollama_only_when_marked(request: pytest.FixtureRequest) -> None:
    if request.node.get_closest_marker("needs_ollama"):
        enable_socket()
        socket_allow_hosts(_LOOPBACK, allow_unix_socket=True)
        return

    if sys.platform == "win32" and request.node.get_closest_marker("needs_loopback"):
        # `--allow-unix-socket` din addopts acopera doar POSIX, unde bucla de
        # evenimente asyncio isi face self-pipe-ul cu socketpair AF_UNIX. Pe
        # Windows, ProactorEventLoop foloseste o pereche AF_INET pe loopback,
        # deci pytest-socket o blocheaza si CADE tot ce porneste o bucla - adica
        # toate testele de dashboard, desi ele nu ating reteaua.
        #
        # Se deschide STRICT loopback-ul: orice host extern ramane blocat, deci
        # garantia din sectiunea 4.1 (zero request-uri catre infrastructura
        # atacatorului) e neatinsa - un domeniu raportat nu e niciodata 127.0.0.1.
        # Vezi tests/test_network_is_blocked.py, care verifica exact asta.
        enable_socket()
        socket_allow_hosts(_LOOPBACK, allow_unix_socket=True)


@pytest.fixture
def corpus_dir() -> Path:
    return CORPUS


@pytest.fixture(autouse=True)
def _temp_database(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Fiecare test primeste o baza de date proprie, in tmp.

    Autouse ca nimeni sa nu scrie din greseala in data/db/triage.sqlite3 -
    fisierul real, cu raportari reale.
    """
    db.use_database(tmp_path_factory.mktemp("db") / "test.sqlite3")
