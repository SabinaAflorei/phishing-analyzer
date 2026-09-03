"""Configurarea sistemului, incarcata o singura data la pornire.

Doua surse, cu roluri diferite, ca sa nu existe doua adevaruri pentru aceeasi
valoare:

- `config/settings.yaml` (fallback `config/settings.example.yaml`) tine TOT ce
  nu e secret: sursa de date, cai, LLM, imbogatire, dashboard.
- `.env` tine DOAR secretele, adica credentialele IMAP. Nimic din ele nu are ce
  cauta intr-un fisier care ajunge in git.

Se citeste prin `get_settings()`, care e memorat cu lru_cache: un singur citit
per proces, si acelasi obiect peste tot.
"""

from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from triage.config import load_yaml_config

logger = logging.getLogger(__name__)


class PathSettings(BaseModel):
    raw_eml_dir: Path = Path("data/raw_eml")
    db_path: Path = Path("data/db/triage.sqlite3")


class LLMSettings(BaseModel):
    enabled: bool = True
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3.1:8b"
    temperature: float = 0.2
    max_input_chars: int = 2000
    timeout_seconds: int = 30

    @field_validator("base_url")
    @classmethod
    def _only_loopback(cls, value: str) -> str:
        """Sectiunea 4.1: modelul ruleaza local. Un base_url extern ar trimite
        continutul mailului raportat la un tert, exact ce interzice foaia."""
        host = value.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
        if host not in {"127.0.0.1", "localhost", "::1", "[::1]"}:
            raise ValueError(
                f"llm.base_url trebuie sa fie pe loopback, nu {host!r}. "
                "Modelul ruleaza local (sectiunea 4.1)."
            )
        return value


class EnrichmentSettings(BaseModel):
    """Imbogatirea externa e singura componenta care are voie sa iasa in retea.
    Implicit oprita - offline-first (sectiunea 4.6)."""

    enabled: bool = False
    private_submission_only: bool = True
    strip_recipient_tokens: bool = True


class DashboardSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000

    @field_validator("host")
    @classmethod
    def _only_loopback(cls, value: str) -> str:
        """Criteriu de acceptanta 8.2: serviciul asculta doar pe 127.0.0.1."""
        if value in {"localhost", "::1"}:
            return value
        try:
            if not ipaddress.ip_address(value).is_loopback:
                raise ValueError
        except ValueError:
            raise ValueError(
                f"dashboard.host trebuie sa fie loopback, nu {value!r} (sectiunea 8.2)."
            ) from None
        return value


class ImapSettings(BaseSettings):
    """Credentiale IMAP, exclusiv din .env. Niciodata din YAML, niciodata din cod."""

    model_config = SettingsConfigDict(
        env_prefix="TRIAGE_IMAP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = ""
    port: int = 993
    user: str = ""
    app_password: str = ""
    folder: str = "INBOX"

    @property
    def configured(self) -> bool:
        return bool(self.host and self.user and self.app_password)


class Settings(BaseModel):
    source: Literal["corpus", "imap"] = "corpus"
    poll_interval_seconds: int = 300
    paths: PathSettings = Field(default_factory=PathSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    enrichment: EnrichmentSettings = Field(default_factory=EnrichmentSettings)
    dashboard: DashboardSettings = Field(default_factory=DashboardSettings)
    imap: ImapSettings = Field(default_factory=ImapSettings)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Configurarea procesului. Citita o singura data, la prima cerere."""
    data = load_yaml_config("settings.yaml")
    data.pop("imap", None)  # credentialele vin doar din .env
    settings = Settings.model_validate(data)
    logger.info(
        "Configurare: sursa=%s, llm=%s (%s), imbogatire=%s",
        settings.source,
        "pornit" if settings.llm.enabled else "oprit",
        settings.llm.model,
        "pornita" if settings.enrichment.enabled else "oprita",
    )
    return settings
