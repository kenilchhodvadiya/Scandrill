# Attack-Graph Engine — Source → Primitive → Sink Reachability
_The core of prompt-inj-v2. Stop thinking in checklists. Think in reachable paths._

An LLM app is a graph. **Nodes** are capabilities and data. **Edges** are injection
primitives that move you from something you control to something you want. A bug is
just **a path from a Source you control to a Sink you want.** Your whole job is to
find one edge the developer didn't know existed.

```
   SOURCE (you influence)  --PRIMITIVE (injection)-->  BEHAVIOR  -->  SINK (value)
```

---

## 1. SOURCE INVENTORY — "what can I get into the model's context?"

Rank each by how much the attacker controls it and whether the victim must act.

| Source | Control | Victim interaction | Notes |
|--------|---------|--------------------|-------|
| Direct chat / API body | Full | Self | Baseline; weakest guardrails on API |
| URL prefill param (`?q=`) | Full | 1 click | P2P one-click (Reprompt, Claudy Day) |
| Uploaded file (PDF/img/csv) | Full | User uploads | 1px text, XMP, annotations, OCR-only |
| Email body | Full | Zero-click if auto-indexed | EchoLeak / ShadowLeak |
| Web page (agent browses) | Full | Zero/1 click | meta, alt, hidden div, JSON-LD, comments |
| Search-indexed page | Full | Zero-click | agent auto-browses → no named URL |
| RAG document | Med–Full | Query-triggered | needs retrieval match (semantic spray) |
| Tool output | Situational | — | any tool returning attacker data = source |
| MCP tool schema | Full (if you host) | — | name/desc/params/enum + Unicode TAG block |
| Peer agent message | Situational | — | A2A session smuggling |
| Metadata (filename, title, author, commit msg) | Full | — | often rendered to model verbatim |
| Image / audio / video | Full | — | steganography, single-frame, subtitles |
| Persistent memory | Med | Delayed | poison once → fires later, cross-session |

> **Creative move:** the best sources are the ones the developer forgot are attacker-controlled — filenames, alt-text, commit messages, tool JSON, a calendar invite title. Trusted-looking channel = lowest scrutiny.

---

## 2. SINK INVENTORY — "what do I actually want to reach?"

| Sink | Impact | How the model reaches it |
|------|--------|--------------------------|
| System prompt | High (secrets/logic) | direct/oblique extraction, encoding |
| Other users' data | Critical | shared RAG/vector DB, cross-tenant context |
| Env vars / secrets | Critical | serialization (LangGrinch), tool that returns key |
| `http`/`fetch` tool | SSRF / exfil | force call w/ attacker URL → IMDS, internal, webhook |
| `email`/`message` tool | Exfil / phishing | force send to attacker w/ context |
| Code exec tool | RCE | force malicious code / `os.system` |
| DB / query tool | Data theft / destroy | text→SQL/Cypher injection |
| File write / config | RCE (auto-load) | write mcp.json / settings.json → CurXecute class |
| Memory store | Persistence | write poisoned memory → ASI06 |
| Downstream agent | Pipeline takeover | inject peer message → ASI07 |
| Rendered markdown image | Exfil channel | `![](trusted-domain/?d=DATA)` |
| Vendor API egress | Exfil channel | Files API to attacker account (Claude pirate) |

---

## 3. THE REACHABILITY MATRIX (fill this per target)

For each **Source you control** (rows) × each **Sink you want** (cols), mark the
primitive that connects them, or `∅` if no edge yet. A single filled cell = a finding.

```
              SysPrompt  OtherUserData  Secrets  SSRF  Email  RCE   DBdump  Persist
Chat/API         D           ∅            ∅       T     T      T     T        ∅
RAG doc          I           I(shared)    ∅       I+T   I+T    I+T   I+T      RAGpoison
Email            I           I            I       I+T   I+T    ∅     ∅        ∅
Web page         I           ∅            ∅       I+T   I+T    I+T   ∅        ∅
MCP schema       FSP         ∅            FSP+chain ∅   ∅      cfg   ∅        ∅
Peer agent       A2A         A2A          A2A     ∅     ∅      ∅     ∅        A2A

Legend: D=direct  I=indirect  T=tool-abuse  FSP=full-schema poisoning
        cfg=config-write→RCE  cfg  cfg  A2A=session smuggling  ∅=no edge yet (try harder)
```

**How to use it:**
1. Fill SOURCE rows from what recon proved you control.
2. Fill SINK cols from tools/data the app exposes.
3. Rank cells by `impact(sink) ÷ effort(primitive)`; attack the top cell first.
4. Every landed primitive can **add a new source row** (e.g., you now control a tool
   output) → re-fill the matrix. Recurse until no higher-impact cell is reachable.

---

## 4. ESCALATION LADDERS — "once I have X, I can always try for Y"

Greedy chaining. Never stop at the first bug; climb.

```
System-prompt leak
  └→ reveals tool names / auth codewords / internal URLs
     └→ target those tools directly / trigger hidden capabilities

Any injection that lands
  └→ can it EXFIL?  (system prompt, user data, env vars)
  └→ can it CALL A TOOL?  (SSRF, email, code, DB, file-write)
  └→ can it PERSIST?  (RAG store, memory, config file)
  └→ does it affect OTHER USERS?  (multi-tenant / shared vector DB)
  └→ is it WORMABLE?  (self-replicates via agent output)

SSRF (via tool)
  └→ 169.254.169.254 IMDS → cloud creds → full account
  └→ internal admin panels / k8s API / Redis (dict://)

File-write / config tool
  └→ mcp.json / settings.json auto-load → RCE (CurXecute/YOLO)
     └→ RCE → creds → lateral movement → wormable

RAG write access
  └→ poison doc → fires in victim's session → cross-tenant theft
     └→ persistent + affects all future queries

Single agent in a pipeline
  └→ A2A session smuggling → corrupt downstream decisions (87% in 4h)
```

---

## 5. IMPACT SCORING (rank paths, write reports)

```
Score a path = Sink value × Reach × Persistence × (1 / Interaction)

Sink value:    secret/RCE/cross-user = 5 ... jailbowl-only = 1
Reach:         all users = 5 ... single self-session = 1
Persistence:   permanent (memory/config) = 3 ... one-shot = 1
Interaction:   zero-click = ×3 ... one-click = ×2 ... heavy multi-turn = ×1

CRITICAL: zero-click cross-user exfil, RCE, cross-tenant, secret disclosure
HIGH:     SSRF, persistent poisoning, partial secret leak, A2A takeover
MEDIUM:   indirect injection needing victim to open specific doc, jailbreak
LOW:      hallucination, DoS, self-only jailbreak
```

> Report the **path**, not the payload: "Source X → primitive P → Sink Y = impact Z."
> That framing is what turns a "jailbreak" (LOW) into "zero-click data exfil" (CRIT).
