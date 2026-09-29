# 10 — Advanced Deobfuscation

## Goal
Recover readable source from obfuscated JS. Obfuscation is a **red flag** — developers hide
something. The deobfuscation payoff rate is significantly higher than on plaintext bundles.

---

## Identify the Obfuscation Type First

```bash
# 1. eval-packed (p,a,c,k,e,d packer — oldest, easiest)
grep -l 'eval(function(p,a,c,k,e,d)' js_files/*.js

# 2. obfuscator.io (most common 2022-2025 — string arrays + control flow flattening)
grep -l '_0x[0-9a-f]\{4,\}' js_files/*.js

# 3. Webpack minified only (not obfuscated — webcrack handles this)
grep -l 'webpackChunk\|__webpack_require__' js_files/*.js

# 4. Base64/hex encoded strings
grep -l 'atob\|fromCharCode\|\\\\x[0-9a-f]\{2\}' js_files/*.js

# 5. Terser/UglifyJS minified (short variable names, no control-flow tricks)
# These are the easiest — js-beautify is enough.
```

---

## Tool 1: webcrack — Webpack Bundle Recovery

Best tool for recovering original module structure from any webpack bundle (minified or obfuscated).
Recovers: module paths, original variable names, split code into files by original source path.

```bash
npm install -g webcrack

# Deobfuscate + recover module structure
webcrack js_files/main.abc123.js -o ./recovered_main/

# Output: recovered_main/
#   src/components/AuthService.js
#   src/api/internal.js           ← internal paths are revealed
#   node_modules/...              ← vendor code separated out
# These are readable source files. Read them like real code.

# Batch all bundles
for f in beautified/*.js; do
  out="deobfuscated/$(basename "$f" .js)"
  webcrack "$f" -o "$out/" 2>/dev/null && echo "[+] $f → $out/"
done

# After recovery, run full analysis pipeline on recovered files
find deobfuscated/ -name "*.js" | xargs jsluice urls  > jsluice_recovered_urls.txt
find deobfuscated/ -name "*.js" | xargs jsluice secrets > jsluice_recovered_secrets.txt
trufflehog filesystem deobfuscated/ --only-verified
```

---

## Tool 2: synchrony — obfuscator.io Deobfuscation

obfuscator.io output has: string-array rotation, control-flow flattening, identifier renaming,
dead code insertion. synchrony (also called `deobfuscator`) reverses all of these.

```bash
npm install -g deobfuscator  # installs as 'synchrony' CLI

# Deobfuscate a single file
synchrony deobfuscate js_files/obf_main.js

# Output: js_files/obf_main-deobfuscated.js
# Now beautify and read
js-beautify js_files/obf_main-deobfuscated.js > readable/obf_main.js

# Batch
for f in js_files/*.js; do
  if grep -q '_0x' "$f"; then  # obfuscator.io signature
    synchrony deobfuscate "$f" 2>/dev/null && echo "[+] deobfuscated: $f"
  fi
done
```

---

## Tool 3: eval-Packer Unwrapping (p,a,c,k,e,d)

```bash
# Node.js intercept-eval approach
node -e "
var fs = require('fs');
var code = fs.readFileSync(process.argv[1], 'utf8');
var realEval = eval;
eval = function(x) {
  fs.writeFileSync(process.argv[1]+'.unpacked.js', x, 'utf8');
  console.log('[+] Unpacked, length:', x.length);
};
try { realEval(code); } catch(e) {}
" "js_files/packed.js"

# Python alternative (safer — no code execution)
python3 - <<'EOF'
import re, sys
code = open(sys.argv[1]).read()
# Match p,a,c,k,e,d packer
m = re.search(r"eval\(function\(p,a,c,k,e,d\)\{.+?\}\('(.+?)',(\d+),(\d+),'(.+?)'\.split\('\|'\)", code, re.DOTALL)
if m:
    packed, radix, count, keywords = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4).split('|')
    def unbase(n, base):
        digits = '0123456789abcdefghijklmnopqrstuvwxyz'
        result, n = 0, n.lower()
        for c in n:
            result = result * base + digits.index(c)
        return result
    def decode(s):
        idx = unbase(s, radix)
        return keywords[idx] if idx < len(keywords) and keywords[idx] else s
    result = re.sub(r'\b([0-9a-z]+)\b', lambda m: decode(m.group(0)), packed)
    print(result[:5000])
else:
    print("[-] No p,a,c,k,e,d packer found")
EOF
```

---

## Tool 4: Base64 / Hex String Extraction

```python
# scripts/decode_embedded_strings.py
"""
Extract and decode Base64/hex/unicode-escaped strings embedded in JS.
Obfuscated code often stores all string literals in an array, base64-encoded.
"""
import re, base64, sys
from pathlib import Path

for f in Path(sys.argv[1] if len(sys.argv)>1 else 'js_files').rglob('*.js'):
    content = f.read_text(errors='ignore')

    # Base64 strings (length > 20 to skip noise)
    b64s = re.findall(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']', content)
    for b in b64s:
        try:
            decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in ['http','api','key','token','password','secret','admin']):
                print(f"[BASE64] {f.name}: {decoded[:150]}")
        except Exception:
            pass

    # Hex-encoded strings \x41\x50\x49 → "API"
    hex_strs = re.findall(r'(?:\\x[0-9a-fA-F]{2}){4,}', content)
    for hs in hex_strs:
        try:
            decoded = bytes.fromhex(hs.replace('\\x', '')).decode('utf-8', errors='ignore')
            if len(decoded) > 3:
                print(f"[HEX] {f.name}: {decoded[:100]}")
        except Exception:
            pass

    # Unicode escapes API → "API"
    uni_strs = re.findall(r'(?:\\u[0-9a-fA-F]{4}){3,}', content)
    for us in uni_strs:
        try:
            decoded = us.encode('utf-8').decode('unicode_escape')
            if any(kw in decoded.lower() for kw in ['api','key','token','http','admin']):
                print(f"[UNICODE] {f.name}: {decoded[:100]}")
        except Exception:
            pass
```

```bash
python scripts/decode_embedded_strings.py js_files/
```

---

## Tool 5: String Array Rotation Recovery (obfuscator.io)

obfuscator.io moves all string literals into an array and accesses them by index after rotation.
The array and its rotation function are always in the first ~200 lines.

```bash
# Extract the string array manually
head -200 js_files/obfuscated.js | grep -oP '\[("[^"]+",\s*){5,}[^]]+\]' | head -3

# Automated: use synchrony or webcrack (both handle this automatically)
# Manual deobfuscation for a single file using node:
node - <<'JSEOF'
const fs = require('fs');
const code = fs.readFileSync('js_files/obfuscated.js', 'utf8');
// Intercept string array access by evaluating just the array setup
const vm = require('vm');
const sandbox = {};
try {
  // Run only the first 300 lines (array + rotation setup)
  const setup = code.split('\n').slice(0, 300).join('\n');
  vm.runInNewContext(setup, sandbox);
  // Now sandbox contains the string array access function
  console.log('[+] String array setup evaluated');
  console.log(JSON.stringify(Object.keys(sandbox)));
} catch(e) { console.error(e.message); }
JSEOF
```

---

## Deobfuscation Decision Tree

```
File contains eval(function(p,a,c,k,e,d)) ?
  → Yes → Node eval intercept (Tool 3)

File contains _0x variables + string arrays ?
  → Yes → synchrony (Tool 2)

File contains __webpack_require__ / webpackChunk ?
  → Yes → webcrack (Tool 1) — recovers original module structure

File contains \x41\x50\x49 or base64 blobs ?
  → Yes → decode_embedded_strings.py (Tool 4)

File looks minified but readable variable names ?
  → js-beautify is enough — no obfuscation, just minification

Source map (.js.map) exists ?
  → sourcemapper / webcrack can use it → full original source, skip deobfuscation
```

---

## After Deobfuscation — Run Full Pipeline Again

Deobfuscated code reveals what the obfuscated version hid. **Always re-run the full analysis:**

```bash
# All newly readable files go through the complete pipeline
DEOBF_DIR=deobfuscated/
find $DEOBF_DIR -name "*.js" > deobf_files.txt

# Static scan
python scripts/static_scan.py $DEOBF_DIR

# Endpoint extraction
find $DEOBF_DIR -name "*.js" | xargs jsluice urls | sort -u > deobf_endpoints.txt
find $DEOBF_DIR -name "*.js" | xargs linkfinder -i - -o cli 2>/dev/null >> deobf_endpoints.txt

# Secret scan
trufflehog filesystem $DEOBF_DIR --only-verified
whispers --target $DEOBF_DIR

# SPA router extraction (now readable after deobfuscation)
grep -rE '(path|route)\s*:\s*["'"'"'][^"'"'"']+["'"'"']' $DEOBF_DIR | sort -u

# Then READ every deobfuscated file end to end — this is the point
```
