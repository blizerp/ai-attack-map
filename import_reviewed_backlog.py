"""Import human-reviewed incident records without replacing the existing database.

Input: reviewed_backlog.json, an array of {"url": ..., "records": [...]}
where records follow the extraction schema in update.py. Only source URLs
already in pending.json are accepted. Run from repository root.
"""
import argparse
import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import update as u
import coverage_collector as collector


def import_reviews(root, reviews, dry_run=True):
    root = Path(root)
    data = u.load_json(root / "attacks.json", {"updated": None, "incidents": []})
    pending = u.load_json(root / "pending.json", {})
    decisions = u.load_json(root / "decisions.json", {})
    geo = u.load_json(root / "geocache.json", {})
    if not isinstance(reviews, list):
        raise ValueError("Review input must be an array")
    # Validate the entire batch before touching the on-disk database.
    data, pending, decisions, geo = map(copy.deepcopy, (data, pending, decisions, geo))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    added = merged = excluded = 0
    seen_urls = set()
    for review in reviews:
        if not isinstance(review, dict) or set(review) != {"url", "records"}:
            raise ValueError("Each review must have exactly url and records")
        url, records = review["url"], review["records"]
        if url in seen_urls or url not in pending:
            raise ValueError("Duplicate or unknown pending source URL")
        seen_urls.add(url)
        if not isinstance(records, list) or not records or len(records) > 8:
            raise ValueError("Each review must contain 1 to 8 records")
        item = pending[url]
        decisions_for_source = []
        for index, rec in enumerate(records):
            if not isinstance(rec, dict) or not set(u.SCHEMA["required"]).issubset(rec):
                raise ValueError("Incomplete reviewed incident record")
            for field in ("decision", "evidence_status", "category", "major_impact"):
                if rec[field] not in u.SCHEMA["properties"][field]["enum"]:
                    raise ValueError("Invalid " + field)
            eligible = (u.eligible_record(rec) and rec["decision"] == "include"
                        and rec["evidence_status"] != "unverified")
            if rec["decision"] == "include" and not eligible:
                raise ValueError("Unsubstantiated include decision")
            decisions_for_source.append({"status": rec["decision"], "reason": rec["decision_reason"], "title": rec["title"]})
            if eligible:
                event_item = dict(item)
                event_item["single_incident"] = len(records) == 1
                if index:
                    event_item["id"] = u.make_id(item["id"], rec["victim"], rec["date"])
                result, _ = collector.merge_record(u, data, event_item, rec, geo, now)
                if result == "added":
                    added += 1
                else:
                    merged += 1
            else:
                excluded += 1
        decisions[url] = {"title": item["title"], "source": item["source"],
                          "checked": now, "policy": u.SELECTION_VERSION,
                          "status": "include" if any(d["status"] == "include" for d in decisions_for_source) else
                                    ("defer" if any(d["status"] == "defer" for d in decisions_for_source) else "exclude"),
                          "reason": "; ".join(d["reason"] for d in decisions_for_source),
                          "decisions": decisions_for_source,
                          "evidence": "manual_review",
                          "item": {k:v for k,v in item.items() if k != "text"}}
        del pending[url]
    if not dry_run:
        # Preserve ingestion's last_success timestamp; manual import is not an API ingestion success.
        data["incidents"].sort(key=lambda i: i.get("last_reported", i["date"]), reverse=True)
        for name, obj in (("attacks.json", data), ("decisions.json", decisions),
                          ("pending.json", pending), ("geocache.json", geo)):
            u.save_json(root / name, obj)
    return {"reviewed_articles": len(seen_urls), "added": added, "merged": merged,
            "not_published": excluded, "pending_remaining": len(pending), "dry_run": dry_run}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Reviewed JSON batch")
    parser.add_argument("--apply", action="store_true", help="Write validated changes")
    args = parser.parse_args()
    reviews = json.loads(Path(args.input).read_text(encoding="utf-8"))
    print(json.dumps(import_reviews(Path(__file__).resolve().parent, reviews, not args.apply), indent=2))
