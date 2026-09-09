"""Client minimal peste serverul local de model. Doar stdlib, doar loopback.

Doua runtime-uri, acelasi contract (`generate` + `available`): Ollama pe
`/api/generate` si orice server cu API OpenAI (llama.cpp, vLLM, LM Studio) pe
`/v1/chat/completions`. Transportul e scris o singura data, in `_request_json`.

Modelul NU decide verdictul. Verdictul e produs de analizorul determinist, iar
modelul doar imbraca dovezile in text romanesc. Daca modelul e picat, lent sau
scoate ceva invalid, drafter-ul cade pe template-ul static si sistemul merge mai
departe - criteriul 8.3.

De ce urllib si nu httpx, care e oricum instalat: httpx e dependinta de test
(TestClient). Aici e nevoie de un singur POST catre 127.0.0.1, iar stdlib il
face in douazeci de randuri. Acelasi tipar ca in scripts/eval_model.py.
"""

from __future__ import annotations

import http.client
import json
import logging
import urllib.error
import urllib.request
from typing import Any

from triage.settings import LLMSettings, get_settings

logger = logging.getLogger(__name__)


class OllamaUnavailable(RuntimeError):
    """Serverul de model e picat, lent sau a raspuns altceva decat ne asteptam."""


# Un singur loc unde se face request-ul si unde se prind erorile. Cei doi clienti
# difera doar prin ruta, corpul cererii si campul din care scot textul; transportul
# era copiat de doua ori, cu aceeasi lista de exceptii scrisa in ambele locuri.
_NETWORK_ERRORS = (
    urllib.error.URLError,
    http.client.HTTPException,
    TimeoutError,
    OSError,
    json.JSONDecodeError,
)


def _request_json(url: str, timeout: int, payload: dict[str, Any] | None = None) -> Any:
    """GET (fara payload) sau POST JSON. Orice esec devine OllamaUnavailable."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(  # noqa: S310 - loopback, validat in settings
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read())
    except _NETWORK_ERRORS as err:
        raise OllamaUnavailable(str(err)) from err


class OllamaClient:
    """Un singur apel: `generate`. Semnatura e cea pe care o cheama drafter-ul."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "llama3.1:8b",
        timeout_seconds: int = 30,
        temperature: float = 0.2,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature

    def generate(self, system_prompt: str, prompt: str, temperature: float | None = None) -> str:
        """Textul generat. Ridica OllamaUnavailable la orice problema.

        `timeout_seconds` e obligatoriu si vine din config: fara el, un model
        blocat ar tine pipeline-ul de ingestie pe loc la nesfarsit.
        """
        body = _request_json(
            f"{self.base_url}/api/generate",
            self.timeout_seconds,
            {
                "model": self.model,
                "system": system_prompt,
                "prompt": prompt,
                "stream": False,
                "keep_alive": "10m",
                "options": {
                    "temperature": self.temperature if temperature is None else temperature,
                    "num_predict": 220,
                },
            },
        )
        if not isinstance(body, dict):
            raise OllamaUnavailable(f"Raspuns neasteptat de la Ollama: {type(body).__name__}")
        return str(body.get("response", "")).strip()

    def available(self) -> bool:
        """Ruleaza Ollama si are modelul cerut? Nu arunca niciodata."""
        try:
            tags = _request_json(f"{self.base_url}/api/tags", timeout=3)
        except Exception:
            return False
        names = {str(m.get("name", "")) for m in tags.get("models", [])}
        # Ollama raporteaza "llama3.1:8b"; un model fara tag e implicit ":latest".
        wanted = self.model if ":" in self.model else f"{self.model}:latest"
        return wanted in names


class OpenAICompatibleClient:
    """Acelasi contract ca OllamaClient, dar peste `/v1/chat/completions`.

    Serverul local nu e mereu Ollama: `llama serve` (llama.cpp), vLLM si LM Studio
    expun API-ul OpenAI. Foaia de task cere un model LOCAL, nu un anume runtime -
    iar llama.cpp ruleaza aceleasi GGUF-uri fara sa instalezi Ollama.

    Ramane la fel de strict pe loopback: base_url e validat in settings.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        model: str = "",
        timeout_seconds: int = 30,
        temperature: float = 0.2,
        disable_thinking: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature
        self.disable_thinking = disable_thinking

    def generate(self, system_prompt: str, prompt: str, temperature: float | None = None) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": 400,
            "stream": False,
        }
        if self.disable_thinking:
            payload["chat_template_kwargs"] = {"enable_thinking": False}

        body = _request_json(f"{self.base_url}/v1/chat/completions", self.timeout_seconds, payload)

        try:
            message = body["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as err:
            raise OllamaUnavailable(f"Raspuns fara 'choices': {body!r:.200}") from err

        text = str(message.get("content") or "").strip()
        if not text and message.get("reasoning_content"):
            # Modelul a consumat tot bugetul pe rationament. Fara asta, drafter-ul
            # ar primi "" si ar cadea tacut pe template, fara sa spui de ce.
            raise OllamaUnavailable(
                "modelul a raspuns doar cu rationament, fara text final "
                "(mareste max_tokens sau lasa llm.disable_thinking pe true)"
            )
        return text

    def available(self) -> bool:
        """Raspunde serverul si cunoaste modelul cerut? Nu arunca niciodata."""
        try:
            body = _request_json(f"{self.base_url}/v1/models", timeout=3)
        except Exception:
            return False
        names = {str(m.get("id", "")) for m in body.get("data", [])}
        # Fara model configurat mergem pe ce serveste el; cu unul, trebuie sa existe.
        return bool(names) and (not self.model or self.model in names)


LLMClient = OllamaClient | OpenAICompatibleClient


def build_llm_client(settings: LLMSettings | None = None) -> LLMClient | None:
    """Clientul configurat, sau None cand LLM-ul e oprit din config.

    None nu e o eroare: e comutatorul din sectiunea Configurare, iar drafter-ul
    stie deja ce sa faca fara client - template static.
    """
    llm = settings if settings is not None else get_settings().llm
    if not llm.enabled:
        logger.info("LLM oprit din configurare. Draft-urile vor folosi template-urile statice.")
        return None

    if llm.api == "openai":
        return OpenAICompatibleClient(
            base_url=llm.base_url,
            model=llm.model,
            timeout_seconds=llm.timeout_seconds,
            temperature=llm.temperature,
            disable_thinking=llm.disable_thinking,
        )

    return OllamaClient(
        base_url=llm.base_url,
        model=llm.model,
        timeout_seconds=llm.timeout_seconds,
        temperature=llm.temperature,
    )
