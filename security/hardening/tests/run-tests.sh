#!/bin/bash
# Run the security/hardening test suite (no root, no network needed).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export PYTHONDONTWRITEBYTECODE=1
exec python3 -m unittest discover -s "$here" -p 'test_*.py' "$@"
