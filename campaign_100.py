"""Persist a measurable 100-incident backlog campaign without resetting baseline."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

# Follow-up audit of the latest batch. Preserve full records, never modify baseline.
HOLD_REASONS = {
    "6033db420afc450f": "Controlled Linux security research; no external compromise established.",
    "31ac03a2cea8acb0": "AI attribution expressly unconfirmed; exposure/remediation report does not establish the recorded theft without further review.",
    "2fafaf9c763f9fb9": "Record explicitly describes failed attempts with no successful exploitation.",
    "acdf7d9610b318d4": "Research demonstration of possible impact; actual unauthorized third-party data theft not established.",
    "23ba3087abf35aa7": "Active vulnerability exploitation reported but no consequential victim impact established in this record.",
    "8a62628b5f9b9760": "Historical Jaguar Land Rover attack cited in a forecast article; hold pending independent new-incident and duplicate review.",
}

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
    # Never delete or exclude baseline records. Store complete held records for review.
    held=[i for i in incidents if str(i.get("id")) in HOLD_REASONS and str(i.get("id")) not in baseline]
    if held:
        archive_path=root/"campaign_quality_hold_followup.json"
        archive=json.loads(archive_path.read_text()) if archive_path.exists() else {}
        for i in held:
            archive[str(i["id"])]={"reason":HOLD_REASONS[str(i["id"])],"record":i}
        archive_path.write_text(json.dumps(archive,ensure_ascii=False,indent=2)+"\n")
        data_ids={str(i["id"]) for i in held}
        attacks["incidents"]=[i for i in incidents if str(i.get("id")) not in data_ids]
        attacks["last_added"]=max((i.get("added","") for i in attacks["incidents"]),default=None)
        (root/"attacks.json").write_text(json.dumps(attacks,ensure_ascii=False,indent=1)+"\n")
        ids-=data_ids
        old["followup_quality_audit"]={"archive":archive_path.name,"held_ids":sorted(archive)}
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
