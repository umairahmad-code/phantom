#!/bin/bash
# PHANTOM Framework — portable installer.
# Installs Python deps and generates a machine-correct desktop launcher.
# Safe to re-run. Does NOT require root (desktop entry installs per-user).
set -e

DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$DIR"

echo "PHANTOM install dir: $DIR"

# ── 1. Python dependencies ────────────────────────────
if [ ! -d "$DIR/.venv" ]; then
    echo "Creating virtualenv (.venv)..."
    python3 -m venv "$DIR/.venv"
fi
echo "Installing Python dependencies..."
"$DIR/.venv/bin/pip" install --quiet --upgrade pip
"$DIR/.venv/bin/pip" install --quiet -r "$DIR/requirements.txt"

# ── 2. Make launcher executable ───────────────────────
chmod +x "$DIR/phantom"

# ── 3. Generate a machine-correct desktop entry ───────
DESKTOP="$DIR/phantom.desktop"
cat > "$DESKTOP" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=PHANTOM Framework
Comment=Authorized security assessment platform
Exec=$DIR/phantom
Path=$DIR
Terminal=false
Categories=Security;Network;Utility;
StartupNotify=true
Icon=utilities-terminal
EOF

# Install it to the per-user applications menu if that dir exists.
APPS="$HOME/.local/share/applications"
if [ -d "$APPS" ] || mkdir -p "$APPS" 2>/dev/null; then
    cp "$DESKTOP" "$APPS/phantom.desktop"
    echo "Desktop entry installed to $APPS/phantom.desktop"
fi

echo ""
echo "✓ Install complete. Launch with:  ./phantom"
echo "  (or find 'PHANTOM Framework' in your applications menu)"
