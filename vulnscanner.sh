#!/usr/bin/env bash
# ============================================================
#  VulnScanner — Shell wrapper launcher
#  Makes the tool executable directly: ./vulnscanner.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-activate venv if it exists
if [ -f "$SCRIPT_DIR/.venv/bin/activate" ]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
fi

# Run scanner with all passed arguments
python3 "$SCRIPT_DIR/scanner.py" "$@"
