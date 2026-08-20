#!/usr/bin/env bash
# Reasigura 700 pe directoare si 600 pe .eml-urile brute. Rulabil oricand.
set -euo pipefail
cd "$(dirname "$0")/.."
find data -type d -exec chmod 700 {} +
find data -type f -exec chmod 600 {} +
echo "permisiuni ok"
