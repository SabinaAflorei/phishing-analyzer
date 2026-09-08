from triage.settings import reload_settings


def test_settings_load_from_example_fallback() -> None:
    """Fara settings.yaml real, cade pe example - CI trebuie sa aiba cu ce lucra."""
    settings = reload_settings()
    assert settings.dashboard.host == "127.0.0.1"  
    assert settings.source in ("corpus", "imap")


def test_llm_settings_defaults_are_safe() -> None:
    settings = reload_settings()
    assert isinstance(settings.llm.enabled, bool)
    assert settings.llm.max_input_chars > 0
    assert settings.llm.timeout_seconds > 0


def test_enrichment_disabled_by_default_offline_first() -> None:
    """Offline-first: imbogatirea externa trebuie sa fie oprita implicit."""
    settings = reload_settings()
    assert settings.enrichment.enabled is False