"""Configurare centralizata, incarcata o singura data la pornire.

Sursa: config/settings.yaml (NU intra in git). Daca lipseste, cade pe
config/settings.example.yaml - acelasi mecanism de fallback ca la
company_domains.yaml (vezi analyzer/__init__.py), ca CI si clonele noi
sa aiba cu ce lucra fara sa expuna date reale.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Any


def _find_config_dir() -> Path:
    current = Path(__file__).resolve().parent
    for _ in range(5):
        candidate = current / "config"
        if candidate.exists() and candidate.is_dir():
            return candidate
        current = current.parent
    return Path(__file__).resolve().parents[2] / "config"


CONFIG_DIR = _find_config_dir()


def _load_raw_yaml() -> dict[str, Any]:
    for name in ("settings.yaml", "settings.example.yaml"):
        path = CONFIG_DIR / name
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
    return {}


class PathsSettings(BaseModel):
    raw_eml_dir: str = "data/raw_eml"
    db_path: str = "data/db/triage.sqlite3"


class LLMSettings(BaseModel):
    enabled: bool = False
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3.1:8b"
    temperature: float = 0.2
    max_input_chars: int = 2000
    timeout_seconds: float = 30.0


class EnrichmentSettings(BaseModel):
    enabled: bool = False
    private_submission_only: bool = True
    strip_recipient_tokens: bool = True


class DashboardSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000

class FetcherSettings(BaseModel):
    imap_retry_attempts: int = 3
    imap_retry_backoff_seconds: float = 5.0
    
class Settings(BaseSettings):
    """Radacina configului. BaseSettings permite si suprascriere prin
    variabile de mediu (ex. TRIAGE_LLM__ENABLED=false), util pentru CI."""

    model_config = SettingsConfigDict(env_prefix="TRIAGE_", env_nested_delimiter="__")

    source: Literal["corpus", "imap"] = "corpus"
    poll_interval_seconds: int = 300

    paths: PathsSettings = Field(default_factory=PathsSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    enrichment: EnrichmentSettings = Field(default_factory=EnrichmentSettings)
    dashboard: DashboardSettings = Field(default_factory=DashboardSettings)
    fetcher: FetcherSettings = Field(default_factory=FetcherSettings) 


_settings: Settings | None = None

def get_settings() -> Settings:
    """Incarca config o singura data (cache la nivel de proces)."""
    global _settings
    if _settings is None:
        raw = _load_raw_yaml()
        _settings = Settings(**raw)
    return _settings


def reload_settings() -> Settings:
    """Fortez re-incarcarea - util in teste, cand schimbi settings.yaml intre cazuri."""
    global _settings
    _settings = None
    return get_settings()


def llm_enabled() -> bool:
    return get_settings().llm.enabled


def get_ollama_client() -> Any:
    from triage.drafter.llm_client import OllamaClient
    llm = get_settings().llm
    return OllamaClient(
        base_url=llm.base_url,
        model=llm.model,
        timeout_seconds=llm.timeout_seconds,
    )


def get_db_path() -> Path:
    return Path(get_settings().paths.db_path)


def get_raw_eml_dir() -> Path:
    return Path(get_settings().paths.raw_eml_dir)