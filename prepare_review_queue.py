"""Prepare a 100-article evidence-review queue; never auto-publish unverified items.

This is a staging tool, not a classification or incident publication tool.
Run with --apply to write review_queue_100.json from the current pending queue.
"""
import argparse
import json
from pathlib import Path
import update as u

def prepare(root, limit=100, apply=False):
    root=Path(root)
    pending=u.load_json(root/"pending.json", {})
    decisions=u.load_json(root/"decisions.json", {})
    if not isinstance(pending,dict):
        raise ValueError("Invalid pending database")
    candidates=[]
    for url,item in sorted(pending.items(),key=lambda pair:(pair[1].get("date",""),pair[0]),reverse=True):
        if not isinstance(item,dict) or not url.startswith("https://"):
            continue
        if decisions.get(url,{}).get("status")=="include":
            continue
        candidates.append({"url":url,"title":item.get("title",""),"date":item.get("date",""),
            "source":item.get("source",""),"excerpt":item.get("text","")[:500],
            "review_status":"needs_source_verification","decision":None,"evidence_urls":[]})
        if len(candidates)>=limit:
            break
    if apply:
        (root/"review_queue_100.json").write_text(json.dumps({"schema_version":1,
            "note":"Research queue only; never publish as verified incidents",
            "candidates":candidates},indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    return {"candidates":len(candidates),"applied":apply,"output":"review_queue_100.json"}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--limit",type=int,default=100)
    p.add_argument("--apply",action="store_true")
    args=p.parse_args()
    if not 1<=args.limit<=500:
        p.error("limit must be 1..500")
    print(json.dumps(prepare(Path(__file__).resolve().parent,args.limit,args.apply),indent=2))
