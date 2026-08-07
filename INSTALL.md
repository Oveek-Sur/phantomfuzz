# ⚙️ Install & Run PhantomFuzz on Kali Linux

Works the same on any Debian/Ubuntu box. Takes ~2 minutes.

> ✅ Requirements: **Python 3.8+**, `git` — both ship with Kali.

---

## 🚀 Quick install (copy-paste)

```bash
# 1) get the code (--recursive pulls the PayloadsAllTheThings payloads)
git clone --recursive https://github.com/Oveek-Sur/phantomfuzz
cd phantomfuzz

# 2) create an isolated environment (REQUIRED on Kali — see note below)
python3 -m venv .venv
source .venv/bin/activate

# 3) install dependencies
pip install -r requirements.txt

# 4) run it
python -m phantomfuzz --help
```

That's it. First real run:

```bash
python -m phantomfuzz auto -u https://target-you-are-allowed-to-test.com
```

---

## ⭐ Make a global `pf` command (optional, recommended)

So you can type `pf` from anywhere instead of activating the venv each time:

```bash
# from inside the phantomfuzz folder, with the venv already created:
sudo tee /usr/local/bin/pf >/dev/null <<EOF
#!/usr/bin/env bash
cd "$(pwd)" && source .venv/bin/activate && exec python -m phantomfuzz "\$@"
EOF
sudo chmod +x /usr/local/bin/pf
```

Now from any directory:

```bash
pf auto -u https://target.com
pf subs -u target.com --probe
```

---

## 🤖 Even quicker: the one-command installer

```bash
git clone --recursive https://github.com/Oveek-Sur/phantomfuzz
cd phantomfuzz
./install.sh          # creates the venv, installs deps, offers to add the `pf` command
```

---

## 📦 Alternative: install as a real package

Inside the activated venv:

```bash
pip install .
phantomfuzz --help    # now available as a command while the venv is active
```

Or with **pipx** (keeps it isolated *and* global — nice on Kali):

```bash
sudo apt install -y pipx
pipx install git+https://github.com/Oveek-Sur/phantomfuzz
phantomfuzz --help
```

---

## 🔁 Update to the latest version

```bash
cd phantomfuzz
git pull
git submodule update --init --depth 1     # refresh the payload set
source .venv/bin/activate && pip install -r requirements.txt
```

---

## 🩹 Troubleshooting

**`error: externally-managed-environment` when you run `pip install`**
Modern Kali (Debian PEP 668) blocks installing into the system Python. Use the
**venv** shown above (recommended). Quick alternatives:
```bash
pipx install .                       # cleanest global install
# or, last resort (not recommended):
pip install -r requirements.txt --break-system-packages
```

**`ModuleNotFoundError: No module named 'aiohttp'`**
The venv isn't active. Run `source .venv/bin/activate` first (or use the `pf`
launcher, which activates it for you).

**`python3-venv` missing**
```bash
sudo apt update && sudo apt install -y python3-venv python3-pip git
```

**Payloads look empty / `payloads --list` is short**
You cloned without submodules. Fix:
```bash
git submodule update --init --depth 1
```

**Want faster scans**
`uvloop` is auto-used when present and is already in `requirements.txt`. The
built-in `attacks/*.txt` cover the common cases; for huge lists use
`-w patt:<category>` (PayloadsAllTheThings).

---

## ✅ Smoke test (prove it works, no external target)

```bash
python -m phantomfuzz payloads --local     # should list 6 attack categories
python -m phantomfuzz auto --help          # should show attack-mode options
```

---

## ⚖️ Use responsibly

Only test systems you **own** or are **explicitly authorized** to test
(your own lab, a bug-bounty/VDP target where automated tools are allowed).
See [README](README.md) and [USAGE.md](USAGE.md) for the full command guide.
