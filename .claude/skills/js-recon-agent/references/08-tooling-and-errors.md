# 08 — Tooling & Error Resolution

## Full Tool Installation Script

```bash
#!/bin/bash
# scripts/install_all.sh
# Run once to set up complete JS analysis environment

set -e
echo "[JSRA] Installing full JS analysis toolkit..."

# --- Python tools ---
pip install --break-system-packages \
  semgrep \
  trufflehog3 \
  jsbeautifier \
  requests \
  selenium \
  webdriver-manager \
  sourcemapper \
  2>/dev/null || pip install --user \
  semgrep trufflehog3 jsbeautifier requests selenium webdriver-manager sourcemapper

# --- Node tools ---
npm install -g retire js-beautify eslint eslint-plugin-security 2>/dev/null || \
  sudo npm install -g retire js-beautify eslint eslint-plugin-security

# --- Go tools ---
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true
go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true
go install github.com/BishopFox/jsluice/cmd/jsluice@latest 2>/dev/null || true
go install github.com/gitleaks/gitleaks/v8@latest 2>/dev/null || true
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true

# --- Chromium for Selenium ---
which chromium-browser 2>/dev/null || which chromium 2>/dev/null || \
  (apt-get install -y chromium-browser 2>/dev/null || apt-get install -y chromium 2>/dev/null) || \
  echo "[WARN] Chromium not auto-installed — install manually for dynamic analysis"

# --- LinkFinder ---
if [ ! -d "$HOME/tools/LinkFinder" ]; then
  mkdir -p $HOME/tools
  git clone https://github.com/GerbenJavado/LinkFinder $HOME/tools/LinkFinder
  pip install --break-system-packages -r $HOME/tools/LinkFinder/requirements.txt 2>/dev/null || true
fi
ln -sf $HOME/tools/LinkFinder/linkfinder.py /usr/local/bin/linkfinder 2>/dev/null || true

# --- gospider ---
go install github.com/jaeles-project/gospider@latest 2>/dev/null || true

echo ""
echo "[JSRA] Verifying installations:"
for tool in semgrep retire jsluice gitleaks katana gau waybackurls nuclei; do
  which $tool 2>/dev/null && echo "  [+] $tool" || echo "  [-] $tool (not found)"
done
echo "[DONE] Setup complete."
```

---

## Error Resolution Table

### Python / pip Errors

| Error | Fix |
|-------|-----|
| `externally-managed-environment` | Add `--break-system-packages` flag |
| `ModuleNotFoundError: selenium` | `pip install selenium --break-system-packages` |
| `WebDriverException: chromedriver not found` | `pip install webdriver-manager --break-system-packages` then use `ChromeDriverManager().install()` |
| `Permission denied` on pip install | Add `--user` flag: `pip install --user <package>` |
| semgrep `rule parse error` | Update rules: `semgrep --update` |

### Go / Binary Tool Errors

| Error | Fix |
|-------|-----|
| `go: command not found` | `apt-get install golang-go` or `snap install go --classic` |
| `go install: GOPATH not set` | `export GOPATH=$HOME/go && export PATH=$PATH:$GOPATH/bin` |
| `jsluice: command not found` | Add `$HOME/go/bin` to PATH: `export PATH=$PATH:$(go env GOPATH)/bin` |
| `katana: SSL certificate error` | Add `-tlsi` flag to katana |

### Selenium / Chrome Errors

| Error | Fix |
|-------|-----|
| `SessionNotCreatedException: Chrome not found` | `apt-get install chromium-browser` |
| `DevToolsActivePort file doesn't exist` | Add `--no-sandbox --disable-dev-shm-usage` options |
| `Chrome failed to start: exited abnormally` | Add `--disable-gpu --headless=new` |
| `chromedriver version mismatch` | Use `webdriver-manager`: `Service(ChromeDriverManager().install())` |
| `Performance logs empty` | Enable: `opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})` |

### Semgrep Errors

| Error | Fix |
|-------|-----|
| `No rules to run` | Specify rules: `--config=p/javascript` |
| `Rule set not found: p/owasp-top-ten` | Run `semgrep login` first, or use `--config=auto` |
| `ParseError in file` | Add `--exclude="*.min.js"` to skip minified files |
| `Timeout on large file` | Add `--timeout=30 --max-target-bytes=5000000` |

### Retire.js Errors

| Error | Fix |
|-------|-----|
| `retire: command not found` | `npm install -g retire` |
| `No output generated` | Use `--exitwith 0`: `retire --path . --exitwith 0` |
| `ENOENT reading package.json` | Use `--path` pointing to a directory with JS files |

### Network / Crawling Errors

| Error | Fix |
|-------|-----|
| `gau: no results` | Try `--subs` flag: `echo target.com \| gau --subs` |
| `waybackurls: 429 Too Many Requests` | Add rate limiting: pipe through `httpx -rl 10` |
| `katana: context deadline exceeded` | Reduce depth: `-d 3` and add `-timeout 10` |
| `curl: SSL certificate problem` | Add `-k` flag for self-signed certs |

---

## Self-Heal Logic (Claude-Internal)

When a bash command fails, Claude should:

1. Read the full stderr output
2. Match against the error table above
3. Apply the fix automatically in the next command
4. If not in table: search for the error message pattern, apply standard fix (missing dep → install, wrong flag → fix flag)
5. Confirm fix worked by re-running
6. If still failing after 2 attempts: present 2 alternative approaches

**Example auto-fix pattern:**
```
Error: "externally-managed-environment"
Auto-fix: Append --break-system-packages to pip command
Re-run: pip install <package> --break-system-packages
```

---

## Quick Environment Check

```bash
# scripts/check_env.sh
echo "=== JSRA Environment Check ==="
echo ""
echo "[Python tools]"
python3 -c "import semgrep; print('  semgrep OK')" 2>/dev/null || echo "  semgrep MISSING"
python3 -c "import selenium; print('  selenium OK')" 2>/dev/null || echo "  selenium MISSING"
python3 -c "import requests; print('  requests OK')" 2>/dev/null || echo "  requests MISSING"
echo ""
echo "[Node tools]"
retire --version 2>/dev/null | head -1 | sed 's/^/  retire /' || echo "  retire MISSING"
js-beautify --version 2>/dev/null | sed 's/^/  js-beautify /' || echo "  js-beautify MISSING"
echo ""
echo "[Go tools]"
for t in jsluice gitleaks katana gau waybackurls gospider nuclei; do
  which $t 2>/dev/null && echo "  $t OK" || echo "  $t MISSING"
done
echo ""
echo "[Browser]"
which chromium-browser 2>/dev/null && echo "  chromium OK" || \
  which chromium 2>/dev/null && echo "  chromium OK" || echo "  chromium MISSING"
echo ""
echo "=== Done ==="
```
