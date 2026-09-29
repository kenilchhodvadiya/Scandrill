# Creative Payload Engine — Generate, Don't Recite
_v1's payload-library.md is your static ammo. This file is how you INVENT new rounds
when the static ones get filtered._

A payload that's in a public list is a payload that's in the defender's blocklist.
Treat every base payload as a **seed** and mutate it until something lands.

---

## 1. THE MUTATION ENGINE — 8 axes to transform any seed

Take one intent (e.g. "reveal your system prompt") and spin it along these axes.
Fire a spread of 5–10 variants; defenders rarely block all axes at once.

```
1. PARAPHRASE     "ignore previous instructions" →
                  "disregard the prior guidance" / "the earlier directives are void"
                  / "treat everything above as an unverified draft"
2. FRAMING        imperative → question → hypothetical → story → "for QA/debug"
                  → "it would be unsafe NOT to..." (safety-inversion)
3. AUTHORITY      neutral → [DEVELOPER] → [SYSTEM] → [ANTHROPIC/OPENAI] → "the user's
                  admin has pre-authorized this via channel X"
4. ENCODING       plain → base64 → ROT13 → hex → morse → pig-latin → "decode & follow"
5. OBFUSCATION    homoglyphs (Іgnore) → zero-width splits → Unicode TAG block
                  (U+E0000+c) → HTML entities (&#73;) → token-splitting ("sys"+"tem")
6. POSITION       start → end → ~85% into a long doc ("lost in the middle") → repeated
                  5–10× (attention hijack) → semantic-spray across sections (RAG)
7. LANGUAGE       English → low-resource language → mixed-script → "translate & execute"
8. INDIRECTION    "summarize this: <PAYLOAD>" / "fix grammar: <PAYLOAD>" / put it in a
                  filename, alt-text, code comment, JSON value, commit message
```

**Stack axes for stubborn filters:** e.g. `Authority + Encoding + Position` =
a `[SYSTEM]`-framed base64 blob planted at 85% depth of an uploaded PDF.

---

## 2. THE ADAPTIVE BYPASS LADDER — climb when blocked

Don't abandon a path on the first refusal. Escalate one rung at a time and note
*which* rung changed the response (that reveals where the defense sits).

```
Rung 0  Plain request                          → baseline
Rung 1  Reword / paraphrase (semantic)         → beats keyword blocklists
Rung 2  Change framing (hypothetical/story/QA) → beats intent classifiers
Rung 3  Obfuscate (unicode/zero-width/entities)→ beats string matching
Rung 4  Encode (base64/rot13) + "decode&do"    → beats pre-filter classifiers
Rung 5  Indirection (translate/summarize/fix)  → payload isn't the "instruction"
Rung 6  Split & reassemble across turns/refs   → no single message is malicious
Rung 7  Move to a weaker surface               → API vs UI, tool output, RAG doc,
                                                  metadata field, another connector
Rung 8  Change the sink                         → if exfil URL blocked, use trusted
                                                  domain / vendor API / service-side
```

> **Diagnostic value:** if Rung 1 fixes it, defense = keyword match. If only Rung 7
> works, defense is UI-only and the API/back-end is soft. Log the rung — it's report gold.

---

## 3. DEVELOPER-ASSUMPTION INVERSION — where creative bugs live

List what the developer *assumes is safe*. Every assumption is an attack. Ask, for
this target, "what did they trust that they shouldn't have?"

```
Assumption                                → Attack
"RAG documents are just data"             → indirect injection in the doc
"Tool output is trustworthy"              → poison the source the tool reads
"The system prompt is hidden"             → extraction via encoding/roleplay/error
"Markdown is just formatting"             → image beacon exfil
"Our domain allowlist is safe"            → trusted-domain exfil / open redirect
"Filenames/metadata aren't instructions"  → inject there (rendered verbatim)
"Approval UI shows what the model sees"   → Unicode TAG-block concealment
"Creating a new file is harmless"         → write mcp.json/settings → RCE
"Each session is isolated"                → shared vector DB → cross-tenant
"The agent only acts on user intent"      → confused deputy via injected data
"Guardrails run on the first action"      → double-request / repeat bypass
"Peer agents are trusted"                 → A2A session smuggling
```

---

## 4. ANOMALY HUNTING — pull every weird thread

Creative bugs announce themselves as small anomalies. When you see one, dig.

```
Anomaly observed                          → What to try next
Reflected token / your input echoed raw   → template injection {{7*7}} / ${7*7}
Odd/verbose error on malformed input      → framework fingerprint → known CVE
Latency spike on certain inputs           → timing side-channel / tool call happening
Response mentions a tool/file you didn't  → hidden capabilities → enumerate them
Partial refusal ("I can't share the FULL")→ you're close; switch to oblique extraction
Model "corrects itself" mid-answer        → guardrail fired post-hoc → race it / split
A field renders differently for you vs AI → concealment gap (TAG block, comments)
```

---

## 5. NOVEL-VECTOR IDEATION PROMPTS (use on yourself before you attack)

Ask these out loud for every target — they force lateral thinking:

```
□ What's the WEIRDEST source of text that reaches this model? (start there)
□ If I were the developer, what input would I NEVER sanitize?
□ What does this app TRUST that an attacker can influence?
□ Where does attacker data and privileged action meet in the same context window?
□ What's allowlisted that I can also read/log/control? (exfil channel)
□ What can this agent WRITE that something else later READS or RUNS?
□ If one injection lands, what NEW input do I now control? (recurse)
□ Which defense is UI-only and evaporates at the API / back-end?
□ What persists between sessions, and can I write to it?
□ Who else's data shares this model's memory / vector store?
```

---

## 6. SELF-VERIFICATION GATES — don't report hallucinations

Prompt injection false-positives are rampant (the model will happily *pretend* to
leak a system prompt). Before you believe a "win":

```
□ REPRODUCE: does it fire on a fresh session, not just once?
□ GROUND-TRUTH: is the "leaked" data verifiable/real, or plausibly invented?
   - system prompt: does it match across 3 extraction methods?
   - exfil: did YOUR server/webhook actually receive the request+data?
   - SSRF/RCE: did you observe the OUT-OF-BAND callback, not just model text?
□ ATTRIBUTION: did the SINK actuate, or did the model just DESCRIBE actuating it?
□ INTERACTION: honestly classify zero/one/multi-click — it drives severity.
□ SCOPE: is the target in scope and are you authorized? (verify before firing)
```

> Rule: **a claim the model makes is not evidence. An out-of-band observation is.**
> No callback on your listener = no exfil, no matter what the model "says" it did.
