#!/usr/bin/env bash
# PhantomFuzz installer for Kali / Debian / Ubuntu.
# Creates an isolated venv, installs deps, and offers a global `pf` command.
set -e

cd "$(dirname "$0")"
ROOT="$(pwd)"
say() { printf '\033[36m[*]\033[0m %s\n' "$1"; }
ok()  { printf '\033[32m[+]\033[0m %s\n' "$1"; }
err() { printf '\033[31m[!]\033[0m %s\n' "$1" >&2; }

# --- prerequisites ----------------------------------------------------------
command -v python3 >/dev/null || { err "python3 not found. sudo apt install -y python3"; exit 1; }
command -v git >/dev/null || { err "git not found. sudo apt install -y git"; exit 1; }
if ! python3 -m venv --help >/dev/null 2>&1; then
  err "python3-venv missing. Run: sudo apt install -y python3-venv"; exit 1
fi

# --- payload submodule ------------------------------------------------------
if [ ! -e payloads/PayloadsAllTheThings/README.md ]; then
  say "fetching PayloadsAllTheThings (submodule)…"
  git submodule update --init --depth 1 || err "submodule fetch failed (non-fatal)"
fi

# --- venv + deps ------------------------------------------------------------
say "creating virtual environment (.venv)…"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
say "installing dependencies…"
pip install -q --upgrade pip
pip install -q -r requirements.txt
ok "dependencies installed"

# --- smoke test -------------------------------------------------------------
python -m phantomfuzz payloads --local >/dev/null 2>&1 && ok "attack library loads" || err "attack library check failed"

# --- optional global `pf` command ------------------------------------------
printf '\033[36m[?]\033[0m Install a global "pf" command to /usr/local/bin? [y/N] '
read -r ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  if sudo tee /usr/local/bin/pf >/dev/null <<EOF
#!/usr/bin/env bash
cd "$ROOT" && source .venv/bin/activate && exec python -m phantomfuzz "\$@"
EOF
  then
    sudo chmod +x /usr/local/bin/pf
    ok "installed — run: pf --help"
  else
    err "could not write /usr/local/bin/pf (need sudo)"
  fi
fi

echo
ok "Done."
echo "  Activate:  source .venv/bin/activate"
echo "  Run:       python -m phantomfuzz auto -u https://target.com"
command -v pf >/dev/null && echo "  Or simply: pf auto -u https://target.com"
echo "  Guide:     see INSTALL.md / USAGE.md"
