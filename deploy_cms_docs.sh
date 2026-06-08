#!/bin/bash
# Deploy offline language documentation to a CMS server.
# Run on the CMS server as a user with sudo access.
#
# Usage: bash deploy_cms_docs.sh [docs_dir] [cms_conf]
#   docs_dir  : where to put docs (default: /var/local/cms/docs)
#   cms_conf  : path to cms.conf (default: /usr/local/etc/cms.conf)

set -euo pipefail

DOCS_DIR="${1:-/var/local/cms/docs}"
CMS_CONF="${2:-/usr/local/etc/cms.conf}"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "=== CMS Documentation Deployer ==="
echo "  docs_dir : $DOCS_DIR"
echo "  cms_conf : $CMS_CONF"
echo ""

sudo mkdir -p "$DOCS_DIR"

# ── 1. C / C++ : cppreference (apt package) ──────────────────────────────────
echo "--- C/C++ docs (cppreference) ---"

if dpkg -l cppreference-doc-en-html &>/dev/null 2>&1; then
    echo "  already installed"
else
    sudo apt-get update -q
    sudo apt-get install -y cppreference-doc-en-html
fi

# The package installs to /usr/share/cppreference/doc/html/
# It may have the HTML directly there or in an 'en/' sub-dir
CPPR_BASE="/usr/share/cppreference/doc/html"
if [ -f "$CPPR_BASE/index.html" ]; then
    CPPR_HTML="$CPPR_BASE"
elif [ -f "$CPPR_BASE/en/index.html" ]; then
    CPPR_HTML="$CPPR_BASE/en"
else
    # Fallback: find it
    CPPR_HTML=$(dirname "$(find /usr/share/cppreference -name "index.html" | head -1)" 2>/dev/null || true)
fi

if [ -n "$CPPR_HTML" ] && [ -d "$CPPR_HTML" ]; then
    sudo ln -sfn "$CPPR_HTML" "$DOCS_DIR/cpp"
    sudo ln -sfn "$CPPR_HTML" "$DOCS_DIR/c"
    echo "  OK: cpp/ and c/ -> $CPPR_HTML"
else
    echo "  ERROR: cppreference HTML not found, skipping C/C++"
fi

# ── 2. Python : official HTML docs from python.org ───────────────────────────
echo ""
echo "--- Python docs ---"

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_DOCS_URL="https://docs.python.org/${PY_VER}/archives/python-${PY_VER}-docs-html.tar.bz2"
PY_ARCHIVE="$TMPDIR/python-docs.tar.bz2"

echo "  downloading Python $PY_VER docs from python.org..."
if wget -q --show-progress -O "$PY_ARCHIVE" "$PY_DOCS_URL"; then
    tar -xjf "$PY_ARCHIVE" -C "$TMPDIR"
    PY_EXTRACTED=$(find "$TMPDIR" -maxdepth 1 -type d -name "python-*-docs-html" | head -1)
    if [ -n "$PY_EXTRACTED" ]; then
        sudo rm -rf "$DOCS_DIR/py"
        sudo cp -r "$PY_EXTRACTED" "$DOCS_DIR/py"
        echo "  OK: py/ installed ($(du -sh "$DOCS_DIR/py" | cut -f1))"
    else
        echo "  ERROR: could not find extracted python docs dir in $TMPDIR"
    fi
else
    echo "  WARNING: download failed for $PY_DOCS_URL"
    echo "           try manually: python3-doc apt package or download from docs.python.org"
fi

# ── 3. Update cms.conf ────────────────────────────────────────────────────────
echo ""
echo "--- cms.conf ---"

if [ ! -f "$CMS_CONF" ]; then
    echo "  WARNING: $CMS_CONF not found"
    echo "  Add manually under contest_web_server:  \"docs_path\": \"$DOCS_DIR\""
else
    sudo python3 - <<PYEOF
import json, sys

conf_path = "$CMS_CONF"
docs_path = "$DOCS_DIR"

with open(conf_path) as f:
    c = json.load(f)

cws = c.get("contest_web_server", {})
old = cws.get("docs_path")
if old == docs_path:
    print(f"  docs_path already set to {docs_path}, no change needed")
    sys.exit(0)

cws["docs_path"] = docs_path
c["contest_web_server"] = cws

with open(conf_path, "w") as f:
    json.dump(c, f, indent=4)

if old:
    print(f"  updated: {old!r} -> {docs_path!r}")
else:
    print(f"  added:   docs_path = {docs_path!r}")
PYEOF
fi

# ── 4. Summary ────────────────────────────────────────────────────────────────
echo ""
echo "=== Result ==="
ls -la "$DOCS_DIR/" 2>/dev/null || echo "  (empty)"

echo ""
echo "=== Restart CWS to apply changes ==="
echo "  sudo systemctl restart cmsContestWebServer@0"
echo "  (or however you start CWS on this machine)"
echo ""
echo "  Then open: http://HOST/Documentazione"
