"""Persist a measurable 100-incident backlog campaign without resetting baseline."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

def refresh(root, initialize=False):
    root=Path(root)
    attacks=json.loads((root/"attacks.json").read_text())
    incidents=attacks.get("incidents",[])
    ids={str(i["id"]) for i in incidents if i.get("id") is not None}
    path=root/"campaign_100.json"
    old=json.loads(path.read_text()) if path.exists() else None
    if old is None:
        if not initialize:
            raise RuntimeError("Campaign not initialized")
        old={"target":100,"baseline_ids":sorted(ids),"started_at":datetime.now(timezone.utc).isoformat()}
    baseline=set(old["baseline_ids"])
    added=sorted(ids-baseline)
    pending=json.loads((root/"pending.json").read_text())
    feed=json.loads((root/"feed_status.json").read_text())
    old.update({"new_unique_incidents":len(added),"new_incident_ids":added,
                "remaining":max(0,old["target"]-len(added)),
                "pending_articles":len(pending),
                "last_ingestion_status":feed.get("status"),
                "last_ingestion_processed":feed.get("processed",0),
                "last_ingestion_errors":feed.get("errors",0),
                "last_ingestion_error_samples":feed.get("error_samples",[]),
                "last_checked_at":datetime.now(timezone.utc).isoformat(),
                "status":"complete" if len(added)>=old["target"] else "running"})
    path.write_text(json.dumps(old,indent=2)+"\n")
    print(json.dumps({k:old[k] for k in ("status","new_unique_incidents","remaining","pending_articles","last_ingestion_status","last_ingestion_errors")}))
    return old

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--initialize",action="store_true")
    a=p.parse_args()
    refresh(Path(__file__).resolve().parent,a.initialize)
