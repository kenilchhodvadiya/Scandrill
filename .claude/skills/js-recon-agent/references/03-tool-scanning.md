# 03 — Tool-Assisted Scanning

## Tools Stack

| Tool | Purpose | Install |
|------|---------|---------|
| semgrep | AST-level SAST for JS/TS | `pip install semgrep --break-system-packages` |
| trufflehog | Secret scanning with live verification | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| retire.js | CVE in JS dependencies | `npm install -g retire` |
| eslint-security | Security linting | `npm install -g eslint eslint-plugin-security` |
| jsluice | Semantic URL/secret extraction (AST-based) | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| linkfinder | Endpoint extraction | `git clone https://github.com/GerbenJavado/LinkFinder` |
| nuclei | Template-based scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| gitleaks | Secret detection | `go install github.com/gitleaks/gitleaks/v8@latest` |
| **webcrack** | **Webpack deobfuscation + module recovery** | `npm install -g webcrack` |
| **whispers** | **Secret scanning with semantic context** | `pip install whispers --break-system-packages` |
| **detect-secrets** | **Yelp's entropy-based secret scanner** | `pip install detect-secrets --break-system-packages` |
| **synchrony** | **JavaScript deobfuscator (obfuscator.io)** | `npm install -g deobfuscator` |
| **secretlint** | **AST-based secret lint, zero FPs** | `npm install -g secretlint @secretlint/secretlint-rule-preset-recommend` |
| **cariddi** | **Fast recursive crawler + JS endpoint extract** | `go install github.com/edoardottt/cariddi/cmd/cariddi@latest` |
| **waymore** | **URL passive discovery (WB+CC+AV+URLScan)** | `pip install waymore --break-system-packages` |

---

## Semgrep — AST-Level JS Security Scan

```bash
# Install security rules
semgrep --config=p/javascript \
        --config=p/react \
        --config=p/nodejsscan \
        --config=p/owasp-top-ten \
        js_files/ \
        --json -o semgrep_results.json \
        --severity=WARNING --severity=ERROR

# Parse results
python3 -c "
import json
with open('semgrep_results.json') as f:
    data = json.load(f)
results = data.get('results', [])
print(f'[SEMGREP] {len(results)} findings')
for r in results[:20]:
    print(f'  [{r[\"extra\"][\"severity\"]}] {r[\"check_id\"]}')
    print(f'  File: {r[\"path\"]}:{r[\"start\"][\"line\"]}')
    print(f'  Code: {r[\"extra\"][\"lines\"].strip()[:120]}')
    print()
"

# Custom semgrep rules for BBH-specific patterns
cat > custom_bbh.yaml << 'EOF'
rules:
  - id: hardcoded-token-in-fetch
    patterns:
      - pattern: fetch($URL, {headers: {Authorization: $TOKEN, ...}, ...})
      - pattern-not: fetch($URL, {headers: {Authorization: $VAR, ...}, ...})
    message: Hardcoded Authorization token in fetch call
    severity: ERROR
    languages: [javascript, typescript]

  - id: client-side-admin-check
    pattern: |
      if ($OBJ.role === "admin") { ... }
    message: Client-side role check — bypassable
    severity: WARNING
    languages: [javascript, typescript]

  - id: prototype-pollution-via-merge
    pattern: Object.assign({}, ...$ARGS)
    message: Potential prototype pollution via Object.assign
    severity: WARNING
    languages: [javascript, typescript]
EOF

semgrep --config=custom_bbh.yaml js_files/ --json -o custom_findings.json
```

---

## TruffleHog — Entropy-Based Secret Scanning

```bash
# Scan local JS directory
trufflehog filesystem js_files/ --json 2>/dev/null | tee trufflehog_results.json

# Scan from a git repo (if cloned)
trufflehog git file://./target_repo/ --json 2>/dev/null | tee trufflehog_git.json

# Parse output
python3 -c "
import json, sys
findings = []
with open('trufflehog_results.json') as f:
    for line in f:
        try:
            findings.append(json.loads(line))
        except: pass
print(f'[TRUFFLEHOG] {len(findings)} secret(s) found')
for f in findings:
    print(f'  Detector: {f.get(\"DetectorName\",\"?\")}')
    print(f'  Raw: {str(f.get(\"Raw\",\"\"))[:80]}')
    print()
"
```

---

## Retire.js — Dependency CVE Scan

```bash
# Scan JS files for known vulnerable libraries
retire --path js_files/ --outputformat json --outputpath retire_results.json 2>/dev/null

# Also scan node_modules if present
retire --path . --outputformat json --outputpath retire_full.json 2>/dev/null

# Parse retire output
python3 -c "
import json
try:
    with open('retire_results.json') as f:
        data = json.load(f)
    for item in data:
        if item.get('results'):
            for r in item['results']:
                for vuln in r.get('vulnerabilities', []):
                    print(f'[RETIRE] {r[\"component\"]} {r[\"version\"]}')
                    print(f'  CVE: {vuln.get(\"identifiers\",{}).get(\"CVE\",\"N/A\")}')
                    print(f'  Severity: {vuln.get(\"severity\",\"?\")}')
                    print(f'  Info: {vuln.get(\"info\",[\"\"])[0][:100]}')
                    print()
except Exception as e:
    print(f'Parse error: {e}')
"
```

---

## Gitleaks — Fast Secret Scan

```bash
gitleaks detect --source js_files/ --report-path gitleaks_report.json --report-format json -v
```

---

## Nuclei — JS-Specific Templates

```bash
# Exposures and misconfigurations in JS
nuclei -l js_master_list.txt \
  -t http/exposures/ \
  -t http/misconfiguration/ \
  -t http/technologies/ \
  -json-export nuclei_js.json \
  -silent

# Specific JS exposure templates
nuclei -l js_master_list.txt \
  -tags "js,exposure,token,secret,api-key" \
  -json-export nuclei_secrets.json
```

---

## ESLint Security Plugin

```bash
# Create temp config
cat > /tmp/.eslintrc.json << 'EOF'
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"],
  "rules": {
    "security/detect-eval-with-expression": "error",
    "security/detect-non-literal-regexp": "warn",
    "security/detect-possible-timing-attacks": "warn",
    "security/detect-unsafe-regex": "error",
    "security/detect-object-injection": "warn"
  }
}
EOF

eslint --no-eslintrc -c /tmp/.eslintrc.json js_files/**/*.js \
  --format json -o eslint_security.json 2>/dev/null
```

---

## Webcrack — Webpack Deobfuscation

```bash
# Deobfuscate a webpack bundle and recover individual modules with real variable names
webcrack js_files/main.abc123.js -o ./deobfuscated/main/

# Batch deobfuscate all bundles
for f in beautified/*.js; do
  webcrack "$f" -o "deobfuscated/$(basename "$f" .js)/" 2>/dev/null && \
    echo "[+] webcrack: $f"
done

# After deobfuscation, run the full analysis pipeline on the recovered modules
# webcrack outputs individual source files named by their original webpack module path
find deobfuscated/ -name "*.js" | xargs jsluice urls  > jsluice_deobf_urls.txt
find deobfuscated/ -name "*.js" | xargs jsluice secrets > jsluice_deobf_secrets.txt
trufflehog filesystem deobfuscated/ --only-verified --json
```

---

## Synchrony / de4js — obfuscator.io Deobfuscation

```bash
# synchrony handles obfuscator.io output (string arrays, control flow flattening, etc.)
# Install: npm install -g deobfuscator  (the 'synchrony' CLI)
synchrony deobfuscate js_files/obfuscated.js

# de4js — browser-based, good for eval-packed code; use programmatically via puppeteer
# For eval(function(p,a,c,k,e,d){...}) packed code:
node -e "
var code = require('fs').readFileSync('js_files/packed.js', 'utf8');
// Intercept eval to capture the unpacked output
var real = eval;
eval = function(x) { require('fs').writeFileSync('deobfuscated/unpacked.js', x); return real(x); };
try { eval(code); } catch(e) {}
"
```

---

## Whispers & Detect-Secrets — Semantic Secret Scanning

```bash
# whispers — context-aware, understands variable assignment semantics (far fewer FPs)
whispers --target js_files/ --output json > whispers_findings.json
python3 -c "
import json
data = json.load(open('whispers_findings.json'))
for f in data:
    print(f'[{f[\"severity\"]}] {f[\"message\"]}')
    print(f'  File: {f[\"file\"]}:{f[\"line\"]}')
    print(f'  Value: {str(f.get(\"value\",\"\"))[:80]}')
"

# detect-secrets — Yelp's engine, supports custom plugins for new token types
detect-secrets scan js_files/ > .secrets.baseline
detect-secrets audit .secrets.baseline
# Parse baseline
python3 -c "
import json
b = json.load(open('.secrets.baseline'))
for fname, secrets in b.get('results', {}).items():
    for s in secrets:
        print(f'[{s[\"type\"]}] {fname}:{s[\"line_number\"]}')
"
```

---

## Secretlint — AST-Based Secret Linting (zero false positives design)

```bash
# secretlint uses AST so it understands string context — not just regex
secretlint js_files/**/*.js --format json > secretlint_results.json 2>/dev/null

# Parse
python3 -c "
import json, sys
data = json.load(open('secretlint_results.json'))
for result in data.get('results', []):
    for msg in result.get('messages', []):
        print(f'[{msg[\"severity\"]}] {result[\"filePath\"]}:{msg[\"loc\"][\"start\"][\"line\"]}')
        print(f'  Rule: {msg[\"ruleId\"]}')
        print(f'  Message: {msg[\"message\"][:120]}')
"
```

---

## Aggregated Scan Runner (v2 — full suite)

```bash
# scripts/run_all_tools.sh
#!/bin/bash
TARGET=${1:-js_files}
DEOBF="deobfuscated"
echo "[JSRA] Running full tool suite on $TARGET"

echo "[0/8] Webcrack deobfuscation..."
mkdir -p $DEOBF
for f in beautified/*.js; do
  webcrack "$f" -o "$DEOBF/$(basename "$f" .js)/" 2>/dev/null
done

echo "[1/8] Semgrep..."
semgrep --config=p/javascript --config=p/owasp-top-ten \
  "$TARGET" "$DEOBF" --json -o semgrep_results.json -q

echo "[2/8] TruffleHog (verified only)..."
trufflehog filesystem "$TARGET" "$DEOBF" --only-verified --json 2>/dev/null > trufflehog_results.json

echo "[3/8] Retire.js..."
retire --path "$TARGET" --outputformat json --outputpath retire_results.json 2>/dev/null

echo "[4/8] Gitleaks..."
gitleaks detect --source "$TARGET" --report-path gitleaks_report.json \
  --report-format json 2>/dev/null

echo "[5/8] JSluice (including deobfuscated)..."
find "$TARGET" "$DEOBF" -name "*.js" | xargs jsluice urls 2>/dev/null | sort -u > jsluice_urls.txt
find "$TARGET" "$DEOBF" -name "*.js" | xargs jsluice secrets 2>/dev/null > jsluice_secrets.txt

echo "[6/8] Whispers..."
whispers --target "$TARGET" --output json > whispers_findings.json 2>/dev/null

echo "[7/8] Secretlint..."
secretlint "$TARGET/**/*.js" --format json > secretlint_results.json 2>/dev/null

echo "[8/8] Nuclei..."
nuclei -l js.txt -t http/exposures/ -t http/misconfiguration/ -silent -json-export nuclei_js.json 2>/dev/null

echo "[DONE] Results: semgrep_results.json, trufflehog_results.json, retire_results.json,"
echo "       gitleaks_report.json, jsluice_*.txt, whispers_findings.json, secretlint_results.json, nuclei_js.json"
```
