"""Criteriu de acceptanta: zero request-uri catre domenii din mail-urile raportate."""

from __future__ import annotations

import socket

import httpx
import pytest
from pytest_socket import SocketBlockedError  # type: ignore[import-untyped]


def test_socket_is_blocked_by_default() -> None:
    with pytest.raises(SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("example.com", 80))


def test_http_client_cannot_reach_a_reported_domain() -> None:
    """Daca cineva adauga un requests/httpx.get pe un URL raportat, testul cade aici."""
    with pytest.raises(SocketBlockedError):
        httpx.get("http://example.com", timeout=2)
