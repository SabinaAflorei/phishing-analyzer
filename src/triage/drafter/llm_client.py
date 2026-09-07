"""Client minimal pentru Ollama (http://127.0.0.1:11434), fara dependente
externe. Expune exact semnatura pe care build_draft() o asteapta deja:
generate(system_prompt, prompt, temperature) -> str.

Orice eroare (retea, timeout, raspuns invalid) se ridica ca OllamaError.
build_draft() o prinde deja intr-un try/except si cade pe template-ul
static - fallback-ul obligatoriu din sectiunea 6.4."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


class OllamaError(RuntimeError):
    pass


@dataclass(slots=True)
class OllamaClient:
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3:8b"
    timeout_seconds: float = 20.0

    def generate(self, system_prompt: str, prompt: str, temperature: float = 0.1) -> str:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read()
        except (urllib.error.URLError, TimeoutError) as err:
            raise OllamaError(f"Ollama indisponibil la {self.base_url}: {err}") from err

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as err:
            raise OllamaError(f"Răspuns invalid de la Ollama (nu e JSON): {err}") from err

        text = parsed.get("response")
        if not text or not isinstance(text, str):
         raise OllamaError("Răspunsul Ollama nu conține câmpul 'response' așteptat.")
        return str(text)