"""Clientul Ollama, fara retea.

`urlopen` e inlocuit prin monkeypatch, deci testele ruleaza cu socket-urile
blocate ca tot restul suitei. Ce se verifica aici sunt exact caile de esec:
timeout, conexiune refuzata, raspuns care nu e JSON, raspuns care nu e dict.
Toate trebuie sa devina OllamaUnavailable, si niciuna nu are voie sa iasa ca
alta exceptie prin drafter.
"""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from triage.llm import OllamaClient, OllamaUnavailable, build_llm_client
from triage.settings import LLMSettings


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self) -> bytes:
        return self.payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _patch_urlopen(monkeypatch: pytest.MonkeyPatch, handler: Any) -> list[dict[str, Any]]:
    """Inlocuieste urlopen si retine ce s-a trimis."""
    calls: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float | None = None) -> Any:
        calls.append(
            {
                "url": request.full_url,
                "timeout": timeout,
                "body": json.loads(request.data) if request.data else None,
            }
        )
        return handler()

    monkeypatch.setattr("triage.llm.urllib.request.urlopen", fake_urlopen)
    return calls


def _ok(text: str = "Bună ziua, Ion,\n\nCorp.\n\nCu stimă,") -> Any:
    return lambda: FakeResponse(json.dumps({"response": text}).encode())


# ---------------------------------------------------------------------------
# Calea fericita
# ---------------------------------------------------------------------------


def test_generate_intoarce_textul(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_urlopen(monkeypatch, _ok())
    client = OllamaClient(model="qwen2.5:7b", timeout_seconds=12, temperature=0.2)

    text = client.generate(system_prompt="sistem", prompt="utilizator")

    assert text.startswith("Bună ziua, Ion,")
    assert calls[0]["url"] == "http://127.0.0.1:11434/api/generate"
    assert calls[0]["timeout"] == 12, "timeoutul trebuie sa ajunga la urlopen"
    assert calls[0]["body"]["model"] == "qwen2.5:7b"
    assert calls[0]["body"]["stream"] is False


def test_temperatura_din_apel_o_bate_pe_cea_din_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_urlopen(monkeypatch, _ok())
    OllamaClient(temperature=0.9).generate(system_prompt="s", prompt="p", temperature=0.1)
    assert calls[0]["body"]["options"]["temperature"] == 0.1


def test_temperatura_implicita_vine_din_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_urlopen(monkeypatch, _ok())
    OllamaClient(temperature=0.35).generate(system_prompt="s", prompt="p")
    assert calls[0]["body"]["options"]["temperature"] == 0.35


# ---------------------------------------------------------------------------
# Caile de esec: toate devin OllamaUnavailable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "eroare",
    [
        urllib.error.URLError("connection refused"),
        TimeoutError("a expirat"),
        OSError("retea picata"),
    ],
)
def test_erorile_de_retea_devin_ollama_unavailable(
    monkeypatch: pytest.MonkeyPatch, eroare: Exception
) -> None:
    def ridica() -> Any:
        raise eroare

    _patch_urlopen(monkeypatch, ridica)
    with pytest.raises(OllamaUnavailable):
        OllamaClient().generate(system_prompt="s", prompt="p")


def test_raspuns_care_nu_e_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_urlopen(monkeypatch, lambda: FakeResponse(b"<html>eroare 502</html>"))
    with pytest.raises(OllamaUnavailable):
        OllamaClient().generate(system_prompt="s", prompt="p")


def test_raspuns_json_care_nu_e_obiect(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_urlopen(monkeypatch, lambda: FakeResponse(b"[1, 2, 3]"))
    with pytest.raises(OllamaUnavailable, match="neasteptat"):
        OllamaClient().generate(system_prompt="s", prompt="p")


def test_raspuns_fara_camp_response(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_urlopen(monkeypatch, lambda: FakeResponse(b'{"done": true}'))
    assert OllamaClient().generate(system_prompt="s", prompt="p") == ""


# ---------------------------------------------------------------------------
# available()
# ---------------------------------------------------------------------------


def test_available_gaseste_modelul(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps({"models": [{"name": "qwen2.5:7b-instruct"}]}).encode()
    _patch_urlopen(monkeypatch, lambda: FakeResponse(payload))
    assert OllamaClient(model="qwen2.5:7b-instruct").available() is True


def test_available_completeaza_tagul_latest(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps({"models": [{"name": "mistral:latest"}]}).encode()
    _patch_urlopen(monkeypatch, lambda: FakeResponse(payload))
    assert OllamaClient(model="mistral").available() is True


def test_available_nu_arunca_niciodata(monkeypatch: pytest.MonkeyPatch) -> None:
    def ridica() -> Any:
        raise urllib.error.URLError("nu ruleaza")

    _patch_urlopen(monkeypatch, ridica)
    assert OllamaClient().available() is False


def test_available_fals_cand_modelul_lipseste(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_urlopen(monkeypatch, lambda: FakeResponse(b'{"models": [{"name": "altul:7b"}]}'))
    assert OllamaClient(model="qwen2.5:7b-instruct").available() is False


# ---------------------------------------------------------------------------
# Configurare
# ---------------------------------------------------------------------------


def test_base_url_extern_e_respins() -> None:
    """Sectiunea 4.1: modelul ruleaza local. Un base_url extern ar trimite
    continutul mailului raportat la un tert."""
    with pytest.raises(ValueError, match="loopback"):
        LLMSettings(base_url="https://api.exemplu-extern.com")


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:11434"])
def test_base_url_pe_loopback_e_acceptat(url: str) -> None:
    assert build_llm_client(LLMSettings(base_url=url)) is not None


def test_clientul_respecta_base_url_ul_din_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_urlopen(monkeypatch, _ok())
    client = build_llm_client(LLMSettings(base_url="http://localhost:9999"))
    assert client is not None
    client.generate(system_prompt="s", prompt="p")
    assert calls[0]["url"].startswith("http://localhost:9999/")
