#!/usr/bin/env python3
"""
Propagate the MANDATORY JS RECON doctrine into every skill's SKILL.md.

Persistent + self-contained: reads the canonical master doctrine and injects it
(after YAML frontmatter, or after the first H1 if a skill has no frontmatter) into
every ~/.claude/skills/*/SKILL.md that does not already contain the current version marker.

Idempotent: skips any file already carrying the marker. To push updated doctrine content,
edit the master, bump VERSION_MARKER here to match the master's new marker, and re-run.

Usage:  python3 ~/.claude/skills/js-recon-agent/propagate-js-recon-doctrine.py
Rollback: every edited file gets a sibling SKILL.md.prejsrecon.bak
"""
import os, glob

HOME = os.path.expanduser("~")
SKILLS_DIR = os.path.join(HOME, ".claude", "skills")
MASTER = os.path.join(SKILLS_DIR, "js-recon-agent", "references",
                      "00-MANDATORY-JS-RECON-DOCTRINE.md")
VERSION_MARKER = "MANDATORY-JS-RECON-DOCTRINE v3"  # bump to v2/etc. when master content changes

with open(MASTER) as f:
    doctrine = f.read().rstrip("\n") + "\n"
assert VERSION_MARKER in doctrine, "master doctrine missing its own version marker"

injected, skipped, no_fm = [], [], []
for skill_md in sorted(glob.glob(os.path.join(SKILLS_DIR, "*", "SKILL.md"))):
    name = os.path.basename(os.path.dirname(skill_md))
    content = open(skill_md).read()
    if VERSION_MARKER in content:
        skipped.append(name)
        continue
    lines = content.splitlines(keepends=True)
    insert_at = None
    if lines and lines[0].strip() == "---":                 # YAML frontmatter -> after closing ---
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                insert_at = i + 1
                break
    if insert_at is None:                                   # no frontmatter
        if lines and lines[0].startswith("# "):             # keep H1 first (skill description source)
            insert_at = 1
        else:
            insert_at = 0
        no_fm.append(name)
    new = "".join(lines[:insert_at]) + "\n" + doctrine + "\n" + "".join(lines[insert_at:])
    bak = skill_md + ".prejsrecon.bak"
    if not os.path.exists(bak):
        open(bak, "w").write(content)
    open(skill_md, "w").write(new)
    injected.append(name)

print(f"INJECTED ({len(injected)}): {', '.join(injected) or 'none'}")
print(f"SKIPPED already-current ({len(skipped)}): {', '.join(skipped) or 'none'}")
print(f"NO-FRONTMATTER ({len(no_fm)}): {', '.join(no_fm) or 'none'}")
