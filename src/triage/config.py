"""Incarcarea fisierelor din config/. Un singur loc, cu fallback pe .example.

De ce fallback: `config/company_domains.yaml` si `config/settings.yaml` sunt in
.gitignore - contin nume de servere interne si credentiale. Pe orice clona noua
si in CI ele lipsesc. Fara fallback, `.get(cheie, [])` intoarce liste goale si
jumatate din reguli devin cod mort care nu se plange niciodata.

Cu fallback, CI are date de lucru din varianta `.example`, iar pe masina reala
fisierul real are prioritate. Datele reale raman in afara git-ului.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def _find_config_dir() -> Path:
    """Cauta directorul 'config' urcand in ierarhia de directoare."""
    current = Path(__file__).resolve().parent
    for _ in range(5):
        candidate = current / "config"
        if candidate.is_dir():
            return candidate
        current = current.parent
    return Path(__file__).resolve().parents[2] / "config"


CONFIG_DIR = _find_config_dir()


def resolve_config_path(file_name: str) -> Path | None:
    """Calea reala a unui fisier de config: cel real, altfel varianta .example."""
    path = CONFIG_DIR / file_name
    if path.is_file():
        return path

    example = path.with_suffix(f".example{path.suffix}")
    if example.is_file():
        logger.warning(
            "%s nu exista, se foloseste %s. Datele reale trebuie puse in %s.",
            path.name,
            example.name,
            path,
        )
        return example

    logger.error("Nu exista nici %s, nici %s.", path, example)
    return None


def load_yaml_config(file_name: str) -> dict[str, Any]:
    """Incarca un YAML din config/, cu fallback pe varianta .example."""
    path = resolve_config_path(file_name)
    if path is None:
        return {}

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def require_keys(config: dict[str, Any], keys: list[str], source: str) -> None:
    """Striga la pornire daca lipseste o cheie asteptata din config.

    `.get(cheie_scrisa_gresit, [])` nu da niciodata eroare, doar tacere - si
    tacerea aia a costat deja doua regresii (vezi istoricul lui
    attachment_rules.yaml).
    """
    missing = [k for k in keys if k not in config]
    if missing:
        logger.error("%s: lipsesc cheile %s", source, ", ".join(missing))
