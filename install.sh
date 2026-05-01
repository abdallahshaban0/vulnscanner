#!/usr/bin/env bash
# ============================================================
#  VulnScanner — One-command installer
#  Usage: bash install.sh
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║        VulnScanner v1.0 — Installer              ║"
echo "║        Ethical Hacking & Pen Testing Tool        ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check Python version ──────────────────────────────────
echo -e "${CYAN}[*]${NC} Checking Python version..."
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[-]${NC} Python3 not found. Please install Python 3.8+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+]${NC} Python $PYTHON_VERSION found."

# ── Check pip ─────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Checking pip..."
if ! python3 -m pip --version &>/dev/null; then
    echo -e "${YELLOW}[!]${NC} pip not found. Installing pip..."
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3
fi
echo -e "${GREEN}[+]${NC} pip is available."

# ── Create virtual environment (recommended) ──────────────
if [ "$1" != "--no-venv" ]; then
    echo -e "${CYAN}[*]${NC} Creating virtual environment (.venv)..."
    python3 -m venv .venv
    source .venv/bin/activate
    echo -e "${GREEN}[+]${NC} Virtual environment activated."
    PYTHON="python"
    PIP="pip"
else
    PYTHON="python3"
    PIP="pip3"
fi

# ── Install dependencies ──────────────────────────────────
echo -e "${CYAN}[*]${NC} Installing dependencies..."
$PIP install --upgrade pip -q
$PIP install -r requirements.txt -q
echo -e "${GREEN}[+]${NC} All dependencies installed."

# ── Make scanner executable ───────────────────────────────
chmod +x scanner.py vulnscanner.sh 2>/dev/null || true

# ── Verify installation ───────────────────────────────────
echo -e "${CYAN}[*]${NC} Verifying installation..."
$PYTHON scanner.py --help > /dev/null 2>&1 && \
    echo -e "${GREEN}[+]${NC} VulnScanner installed and working!" || \
    echo -e "${RED}[-]${NC} Something went wrong. Check error output above."

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗"
echo -e "║  Installation Complete!                          ║"
echo -e "║                                                  ║"
if [ "$1" != "--no-venv" ]; then
echo -e "║  Activate venv first:  source .venv/bin/activate ║"
fi
echo -e "║  Then run:  python scanner.py --help             ║"
echo -e "║  Or:        ./vulnscanner.sh -t example.com      ║"
echo -e "╚══════════════════════════════════════════════════╝${NC}"
