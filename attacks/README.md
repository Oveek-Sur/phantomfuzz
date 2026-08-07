# 🎯 Attack payload library

This folder holds the payloads PhantomFuzz's `auto` console fires. **Each file is
one attack category** — plain text, one payload per line, `#` lines ignored.

| File | Attack | Detected by |
|------|--------|-------------|
| `traversal.txt` | 📁 Path traversal | `/etc/passwd` (`root:...:0:0:`) / `win.ini` in the response |
| `lfi.txt` | 📁 Local File Inclusion | passwd / `/proc` env / PHP-wrapper base64 output |
| `sqli.txt` | 💉 SQL injection | DB error text, or a time-based delay |
| `xss.txt` | 🔥 Reflected XSS | the `PHXMARK` marker + payload reflected **un-escaped** |
| `redirect.txt` | ↪️ Open redirect | a 30x `Location:` pointing at `evil.example.com` |
| `ssrf.txt` | ↪️ SSRF | cloud-metadata signatures (flagged as a *candidate*) |

## ➕ Add your own payloads

Just open any file and add lines — no code, no restart needed:

```bash
echo '../../../../../../etc/shadow' >> attacks/traversal.txt
echo "' OR SLEEP(10)-- -"          >> attacks/sqli.txt
```

Notes:
- **XSS**: include the literal `PHXMARK` somewhere in the payload so the tool can
  tell *your* injection apart from coincidental page text. Payloads without it
  still work — they're matched verbatim.
- **Redirect**: keep `evil.example.com` as the target host so hits are detected.
- Want the *huge* lists too? `auto` can also pull
  [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
  via `-w patt:<category>` — this folder is your curated, editable default.

## 🔢 How many payloads are loaded

```bash
python -m phantomfuzz payloads --local     # counts every category in this folder
```
