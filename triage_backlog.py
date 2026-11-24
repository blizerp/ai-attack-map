"""Conservative, no-API triage of clearly non-incident article headlines.

This never creates incidents and never deletes uncertain reports. A title must
match an explicit exclusion category; incident-related words veto exclusion.
"""
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import update as u

# Require whole-title semantics, not broad keywords like "AI" or "security".
EXCLUSIONS = [
 ("event promotion", r"\b(?:webinar|conference|summit|workshop|early bird|register now|upcoming event|call for speakers)\b"),
 ("job or personnel news", r"\b(?:appoints new|named chief|names new|joins as|hiring for|career advice|job openings)\b"),
 ("funding or corporate transaction", r"\b(?:raises? \$|secures? \$|funding round|series [a-f] funding|acquires? (?:startup|company)|announces acquisition)\b"),
 ("general guidance", r"\b(?:best practices|how to protect|tips for|guide to|getting started with|what you need to know about|five warning signs|top \d+ tips|explained: how to)\b"),
 ("regulation or policy", r"\b(?:privacy rule|new regulations|regulatory update|compliance checklist|policy framework|proposed rule|legislation|government nomination)\b"),
 ("legal-only retrospective", r"\b(?:settlement|settles lawsuit|pleads guilty|sentenced to prison|court ruling|fined for|class action settlement)\b"),
 ("product release", r"\b(?:launches new|unveils new|introduces new|announces new product|now available|product update|new features for)\b"),
]
# Never discard reports suggesting actual compromise, even if the title also
# references a court, a patch, an acquisition, or a product.
VETO = re.compile(r"\b(?:breach|hacked|attack(?:ed|s)?|ransomware|compromis(?:e|ed)|stolen|intrusion|exfiltrat|leak(?:ed)?|malware|exploit(?:ed|ation)?|victim|disrupt(?:ed|ion)?|unauthori[sz]ed|hijack(?:ed)?|supply.chain attack)\b", re.I)


def reason_for(item):
    title = str(item.get("title") or "")
    if VETO.search(title):
        return None
    for category, pattern in EXCLUSIONS:
        if re.search(pattern, title, re.I):
            return category
    return None


def run(root, limit=100, apply=False):
    root = Path(root)
    pending = u.load_json(root / "pending.json", {})
    decisions = u.load_json(root / "decisions.json", {})
    if not isinstance(pending, dict) or not isinstance(decisions, dict):
        raise ValueError("Invalid queue or decisions database")
    selected = []
    for url, item in pending.items():
        reason = reason_for(item)
        if reason and url.startswith("https://"):
            selected.append((url, item, reason))
            if len(selected) == limit:
                break
    if not selected:
        return {"selected": 0, "pending_remaining": len(pending), "applied": False}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for url, item, category in selected:
        if url in decisions and decisions[url].get("status") == "include":
            raise ValueError("Refusing to overwrite included incident review: " + url)
    if apply:
        for url, item, category in selected:
            reason = "Title-only conservative exclusion: " + category + "; no reported incident in headline. Re-review if new incident evidence emerges."
            decisions[url] = {
                "title": item.get("title", ""), "source": item.get("source", ""),
                "checked": now, "policy": u.SELECTION_VERSION, "status": "exclude",
                "reason": reason, "decisions": [{"status":"exclude", "reason":reason, "title":item.get("title","")}],
                "evidence": "deterministic_headline_triage",
                "item": {k:v for k,v in item.items() if k != "text"},
            }
            del pending[url]
        u.save_json(root / "decisions.json", decisions)
        u.save_json(root / "pending.json", pending)
    return {"selected":len(selected), "pending_remaining":len(pending),
            "applied":apply, "categories":{category:sum(x[2]==category for x in selected) for _,_,category in selected}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.limit <= 500:
        parser.error("--limit must be between 1 and 500")
    print(json.dumps(run(Path(__file__).resolve().parent, args.limit, args.apply), indent=2))
