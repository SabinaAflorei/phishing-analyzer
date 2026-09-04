"""Client minimal peste Ollama. Doar stdlib, doar loopback.

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
    """Ollama e picat, lent sau a raspuns altceva decat ne asteptam."""


class OllamaClient:
    """Un singur apel: `generate`. Semnatura e cea pe care o cheama build_draft."""

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

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - loopback, validat in settings
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=self.timeout_seconds
            ) as response:
                body = json.loads(response.read())
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as err:
            raise OllamaUnavailable(str(err)) from err

        if not isinstance(body, dict):
            raise OllamaUnavailable(f"Raspuns neasteptat de la Ollama: {type(body).__name__}")
        return body

    def generate(self, system_prompt: str, prompt: str, temperature: float | None = None) -> str:
        """Textul generat. Ridica OllamaUnavailable la orice problema.

        `timeout_seconds` e obligatoriu si vine din config: fara el, un model
        blocat ar tine pipeline-ul de ingestie pe loc la nesfarsit.
        """
        body = self._post(
            "/api/generate",
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
        return str(body.get("response", "")).strip()

    def available(self) -> bool:
        """Ruleaza Ollama si are modelul cerut? Nu arunca niciodata."""
        try:
            request = urllib.request.Request(f"{self.base_url}/api/tags")  # noqa: S310
            with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310
                tags = json.loads(response.read())
        except Exception:
            return False
        names = {str(m.get("name", "")) for m in tags.get("models", [])}
        # Ollama raporteaza "llama3.1:8b"; un model fara tag e implicit ":latest".
        wanted = self.model if ":" in self.model else f"{self.model}:latest"
        return wanted in names


def build_llm_client(settings: LLMSettings | None = None) -> OllamaClient | None:
    """Clientul configurat, sau None cand LLM-ul e oprit din config.

    None nu e o eroare: e comutatorul din sectiunea Configurare, iar drafter-ul
    stie deja ce sa faca fara client - template static.
    """
    llm = settings if settings is not None else get_settings().llm
    if not llm.enabled:
        logger.info("LLM oprit din configurare. Draft-urile vor folosi template-urile statice.")
        return None
    return OllamaClient(
        base_url=llm.base_url,
        model=llm.model,
        timeout_seconds=llm.timeout_seconds,
        temperature=llm.temperature,
    )
