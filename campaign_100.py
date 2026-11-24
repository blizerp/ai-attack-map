"""Persist a measurable 100-incident backlog campaign without resetting baseline."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

# Follow-up audit of the latest batch. Preserve full records, never modify baseline.
HOLD_REASONS = {
    "b1c27b067e00ac4a": "Same October LiteLLM malicious package release as baseline e2e13fe6f7503c25; different publication/event date and victim wording do not establish a separate compromise.",
    "e5d92145d0f8de47": "Chainstack incident overlaps baseline a7cfb57f33eb6570; stored quote supplies no distinct compromise details.",
    "8000e3bea6d7298a": "Second Fireworks incident of October 24 overlaps campaign record 9c255d81510cbc8a (downstream Notion data). Retain one underlying event pending reconciliation.",
    "40183598d66106bb": "Same KeyDrift event and same source already present in baseline 4dc4a1512003044a.",
    "4bf14ff9a2059f14": "Potential overlap with baseline Mexican government AI-assisted breach 8a983ded01bbaf68; stored historical excerpt does not establish separate event.",
    "a250e26db6d2c877": "Exploit attempt and precautionary server rebuild; stored evidence does not establish successful compromise or qualifying service impact.",
    "d24b286bd0afa7a2": "Public credentials tested by researchers; no unauthorized adversary access or separate consequential event established by stored evidence.",
    "c61f357272763219": "General targeting and vulnerability report; stored evidence describes possible access, not distinct observed compromise.",
    "a8be3b8eec59e8e1": "Stored evidence describes hypothetical exploitation capability, not observed compromise.",
    "25fc86adddd45273": "Same October 26 UNM Health disruption in baseline 62c149c3423ae5e2.",
    "93d7838ec5b0c895": "Conditional vulnerability advisory, not observed incident.",
    "fcbdd6eb50849ff1": "Same Norwegian Azure incident already in baseline 48dd2a3cc8d92863.",
    "5c22cf2f6e397964": "Norwegian energy follow-up overlaps baseline 48dd2a3cc8d92863; hold pending separate incident evidence.",
    "1c5879993c205ebc": "Overlaps shared financial-services vendor breach f48d0e7cb697eb9b.",
    "5db456fb2a3a7714": "Overlaps shared financial-services vendor breach f48d0e7cb697eb9b.",
    "32c3eee60443203b": "Overlaps shared financial-services vendor breach f48d0e7cb697eb9b.",
    "42157daee7184bad": "Malicious Claude extension follow-up overlaps baseline e3ed66e626b0480b.",
    "36413c2be5b317d5": "Cursor malicious extension overlaps baseline e3ed66e626b0480b.",
    "c8153a7742d121f7": "Record describes researcher demonstration, not a separate external compromise.",
    "36ab8a60a7cbcf3d": "Same generic FBI ARTEX advisory as 7a13ce26cfc41d15; no separate incident shown.",
    "7a13ce26cfc41d15": "Generic FBI advisory about existing ARTEX campaigns, no separate attributable incident in record.",
    "51de823e3249f6e0": "Same Hugging Face incident already in baseline 45ca558620ed06e8.",
    "7f915785a3ab8377": "Same Apple signing-shop campaign in baseline 095ce1e6ac2f4401.",
    "14589e15f7d0133e": "Same source and gaming-account campaign as baseline 4643c116713e48fb; hold pending distinct-event evidence.",
    "1e7b9b662485974e": "Same Vapor Panda campaign in baseline 8393c367c02ad6f3.",
    "40d940aeb82f0077": "N-central precautionary shutdown overlaps 8835ca47eb0cc33f and baseline ba511006af09c577.",
    "8835ca47eb0cc33f": "Precautionary N-central shutdown reported in connection with already tracked attack; hold pending separate incident evidence.",
    "227ea0f9f03bf5cc": "Aggregate hospital impact study, not a distinct incident.",
    "286d5ff395a793bd": "Internal evaluation with no reported sensitive data transfer.",
    "921eed2ec227c9be": "Warning of possible attacks, no distinct actual event in record.",
    "837fc491f960607f": "Record describes demonstrated capability; no distinct real-world victim established.",
    "9cae37f54566134b": "Vulnerability capability report; no observed exploitation established in record.",
    "5bd0bbf19ecb788e": "Trezor Safe 5 implant report overlaps baseline e9ba6f2b40b4d6cf.",
    "af77d8a5b0044ab6": "Same Ivanti chained zero-day attack in baseline f308e7abc49980c1 and 2544e4d3fcebdd95.",
    "346a9555131efdd6": "Same EMERCOM incident in baseline e3b5363a9ef87983.",
    "d55b06e56457a51b": "Same DebugBear/Polymarket incident in baseline 83273d8d85f8311b.",
    "5a8cea201a2f1a3a": "Same Poryadok outage in baseline 1ec6874f660c4580.",
    "c949d6c620573589": "Same DHS leak in baseline 0e3249a520322cec.",
    "36e93cf621cdd97b": "Combines two already tracked Silent Lynx incidents 9e2577dde70bedd5 and 5c5663b52012eebf.",
    "03d0a4678698c8cc": "Same Sutherland breach in baseline c93dd5993e0b955e.",
    "f5589d7d68325a40": "Same Santa Barbara Endodontics breach in baseline 47995a29ec9b3ee7.",
    "3d2dbbf7ed5770ce": "Same Hollister Family Dental breach in baseline b55b5cdcb61ab8da.",
    "38520d8e50fdcea0": "Same Sogou DNS hijacking in baseline dfc46ba6ad0a657f.",
    "c10049381428bdc3": "Same UNM Health event in baseline 62c149c3423ae5e2.",
    "641386aa66359600": "General threat-intelligence framework report without a distinct affected victim or campaign outcome in record.",
    "2cc8234a65db739f": "Unspecified aggregate health-sector breach report, no individually distinguishable incident.",
    "9a8a1b6ecac8bb72": "Sentencing follow-up about historical media hacks; no new incident established.",
    "d60fe79bc501a73f": "Exploitation report lacks documented affected system or observed consequential impact in record.",
    "db35726f2a94b8f2": "Combines separate vulnerability reports and overlaps Apache Axis records; hold pending distinct observed impacts.",
    "18fa95a1ad3755a9": "Potential overlap with baseline identity-document marketplace leak f1a25319701f5382; distinct breach not established in stored record.",
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
        # Reconcile independently reviewed cross-source duplicates with the canonical
        # baseline record. Preserve the held record and its evidence in the archive;
        # attach only the alternate source, not its unverified impact assertions.
        canonical_by_held_id = {"b1c27b067e00ac4a": "e2e13fe6f7503c25"}
        by_id = {str(i.get("id")): i for i in incidents}
        for i in held:
            canonical_id = canonical_by_held_id.get(str(i.get("id")))
            canonical = by_id.get(canonical_id)
            if canonical is not None and canonical_id in baseline and i.get("source_url"):
                urls = {canonical.get("source_url")} | {s.get("url") for s in canonical.get("more_sources", [])}
                if i["source_url"] not in urls:
                    canonical.setdefault("more_sources", []).append({"name": i.get("source_name", "Additional report"), "url": i["source_url"]})
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
