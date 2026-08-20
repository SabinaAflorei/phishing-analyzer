#!/usr/bin/env bash
# Criteriu de acceptanta: serviciul asculta doar pe 127.0.0.1.
set -euo pipefail
if ss -ltnp 2>/dev/null | grep -E '0\.0\.0\.0:(8000|11434)|\[::\]:(8000|11434)'; then
    echo "ESEC: exista un serviciu expus in afara loopback-ului" >&2
    exit 1
fi
echo "OK: nimic expus in afara 127.0.0.1 pe 8000/11434"
