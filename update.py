#!/usr/bin/env python3
"""Pull security news, keep AI-related cyber incidents, write attacks.json for the map.

Run by GitHub Actions every 6 hours. Needs OPENAI_API_KEY in the environment.
Optional env: OPENAI_MODEL (default gpt-4o-mini), MAX_NEW_ITEMS (default 150).
"""
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import feedparser
import requests
from openai import OpenAI

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(ROOT, "attacks.json")
SEEN_PATH = os.path.join(ROOT, "seen.json")
GEO_PATH = os.path.join(ROOT, "geocache.json")

MODEL = os.environ.get("OPENAI_MODEL") or "gpt-4o-mini"
MAX_NEW = int(os.environ.get("MAX_NEW_ITEMS") or 150)
UA = "ai-attack-map/1.0 (github pages hobby project)"

FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "The Record": "https://therecord.media/feed",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}
TRACKER_NAME = "AI agent attack tracker"
TRACKER_REPO = "https://github.com/webpro255/awesome-ai-agent-attacks"
TRACKER_RAW = [
    "https://raw.githubusercontent.com/webpro255/awesome-ai-agent-attacks/main/README.md",
    "https://raw.githubusercontent.com/webpro255/awesome-ai-agent-attacks/master/README.md",
]

# Cheap pre-filter so the model only sees plausibly relevant news items.
KEYWORDS = re.compile(
    r"\b(AI|A\.I\.|artificial intelligence|LLMs?|language models?|GPT\w*|ChatGPT|OpenAI|Claude|"
    r"Anthropic|Gemini|Copilot|agents?|agentic|deepfakes?|voice[- ]clon\w*|machine learning|MCP|"
    r"model context protocol|prompt injection|Hugging ?Face|LangChain|Langflow|LiteLLM|Ollama)\b",
    re.I,
)

SYSTEM_PROMPT = """You extract structured records of real cyber incidents involving AI from security news text.
Use ONLY facts in the provided text. Never invent names, attribution, numbers, or motives. Write "Not reported" for any field the text doesn't cover.

relevant = true only if the text describes a specific, real incident, campaign, intrusion, fraud, or actively exploited/malicious event where AI is involved:
- using_ai: attackers used AI, LLMs, deepfakes, or voice cloning
- by_ai_agent: an AI agent itself carried out unauthorized actions
- on_ai_system: AI systems, agent platforms, AI packages, or the AI supply chain were attacked or compromised
relevant = false for opinion, predictions, surveys, statistics roundups, product launches, marketing, vulnerability disclosures with no reported exploitation, and incidents where AI plays no role.

attacker: state who is reported or suspected AND by whom (e.g. "Attributed by Mandiant to ..."). Never state attribution more strongly than the source does.
where: human-readable location of the victim(s). If the victim is a product or package, use the affected vendor's headquarters if known. Otherwise "No fixed location".
geocode_query: a place a geocoder can resolve for "where", city-level if stated, else country (e.g. "Seoul, South Korea", "Germany"). Null when there is no fixed location.
date: YYYY-MM-DD of the incident or its disclosure. Use the published date given if nothing more specific is stated.
duplicate_of: if this describes the same incident as one in the provided list of already-tracked incidents, return that incident's id; otherwise null.
title: under 90 characters, plain and factual. Other fields: 1-2 short sentences each."""

TEXT = {"type": "string"}
SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "relevant": {"type": "boolean"},
        "category": {"type": "string", "enum": ["using_ai", "by_ai_agent", "on_ai_system"]},
        "title": TEXT, "date": TEXT, "victim": TEXT, "attacker": TEXT,
        "what": TEXT, "ai_role": TEXT, "why": TEXT, "where": TEXT,
        "geocode_query": {"type": ["string", "null"]},
        "duplicate_of": {"type": ["string", "null"]},
    },
    "required": ["relevant", "category", "title", "date", "victim", "attacker", "what",
                 "ai_role", "why", "where", "geocode_query", "duplicate_of"],
}


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)


def make_id(*parts):
    return hashlib.sha1("|".join(p or "" for p in parts).encode()).hexdigest()[:16]


def clean(html, limit=2500):
    text = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", text).strip()[:limit]


def fetch_feeds():
    items = []
    for name, url in FEEDS.items():
        try:
            feed = feedparser.parse(url, agent=UA)
        except Exception as e:
            print(f"feed failed: {name}: {e}")
            continue
        for e in feed.entries:
            title, link = e.get("title", ""), e.get("link", "")
            text = clean(e.get("summary", ""))
            if not KEYWORDS.search(f"{title} {text}"):
                continue
            t = e.get("published_parsed") or e.get("updated_parsed")
            date = datetime(*t[:6]).date().isoformat() if t else ""
            items.append({"id": make_id(link, title), "title": title, "url": link,
                          "text": text, "date": date, "source": name})
        print(f"{name}: {len(feed.entries)} entries")
    return items


def fetch_tracker():
    for url in TRACKER_RAW:
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=30)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        items = []
        for sec in re.split(r"(?m)^###\s+", r.text)[1:]:
            header, _, body = sec.partition("\n")
            m = re.match(r"(\d{4}-\d{2}-\d{2})\s*[-–—]\s*(.+)", header.strip())
            if not m:
                continue
            body = re.split(r"(?m)^##\s", body)[0]
            link = re.search(r"https?://[^\s)\]>\"']+", body)
            items.append({
                "id": make_id("tracker", m.group(1), m.group(2)),
                "title": m.group(2).strip(), "url": link.group(0) if link else TRACKER_REPO,
                "text": clean(body), "date": m.group(1), "source": TRACKER_NAME,
            })
        print(f"tracker: {len(items)} entries")
        return items
    print("tracker: unavailable")
    return []


def extract(client, item, tracked):
    known = "\n".join(f"{t['id']}: {t['title']}" for t in tracked) or "(none yet)"
    user = (f"Already-tracked incidents:\n{known}\n\n---\n"
            f"Source: {item['source']}\nPublished: {item['date']}\nTitle: {item['title']}\n"
            f"URL: {item['url']}\n\n{item['text']}")
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}],
        response_format={"type": "json_schema",
                         "json_schema": {"name": "incident", "strict": True, "schema": SCHEMA}},
    )
    return json.loads(resp.choices[0].message.content)


def geocode(query, cache):
    if not query:
        return None
    key = query.strip().lower()
    if key in cache:
        return cache[key]
    try:
        r = requests.get("https://nominatim.openstreetmap.org/search",
                         params={"q": query, "format": "json", "limit": 1},
                         headers={"User-Agent": UA}, timeout=30)
        time.sleep(1.1)  # Nominatim usage policy: max 1 request/second
        hits = r.json()
    except Exception as e:
        print(f"geocode failed for {query!r}: {e}")
        return None  # not cached, retried next run
    cache[key] = [float(hits[0]["lat"]), float(hits[0]["lon"])] if hits else None
    return cache[key]


def main():
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY is not set")

    data = load_json(DATA_PATH, {"updated": None, "incidents": []})
    seen_list = load_json(SEEN_PATH, [])
    seen = set(seen_list)
    geo = load_json(GEO_PATH, {})

    candidates = [c for c in fetch_tracker() + fetch_feeds() if c["id"] not in seen]
    candidates.sort(key=lambda c: c["date"], reverse=True)
    candidates = candidates[:MAX_NEW]
    print(f"{len(candidates)} new items to check with {MODEL}")

    client = OpenAI()
    added = merged = 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    by_id = {i["id"]: i for i in data["incidents"]}

    for c in candidates:
        tracked = sorted(data["incidents"], key=lambda i: i["date"], reverse=True)[:80]
        try:
            rec = extract(client, c, tracked)
        except Exception as e:
            print(f"extract failed ({c['url']}): {e}")
            continue  # not marked seen, retried next run
        seen.add(c["id"])
        seen_list.append(c["id"])
        if not rec["relevant"]:
            continue

        dup = by_id.get(rec["duplicate_of"] or "")
        if dup:
            urls = {dup["source_url"]} | {s["url"] for s in dup.get("more_sources", [])}
            if c["url"] not in urls:
                dup.setdefault("more_sources", []).append({"name": c["source"], "url": c["url"]})
            merged += 1
            continue

        coords = geocode(rec["geocode_query"], geo)
        inc = {
            "id": c["id"], "title": rec["title"], "date": rec["date"] or c["date"],
            "category": rec["category"], "victim": rec["victim"], "attacker": rec["attacker"],
            "what": rec["what"], "ai_role": rec["ai_role"], "why": rec["why"], "where": rec["where"],
            "lat": coords[0] if coords else None, "lon": coords[1] if coords else None,
            "source_name": c["source"], "source_url": c["url"], "added": now,
        }
        data["incidents"].append(inc)
        by_id[inc["id"]] = inc
        added += 1
        print(f"+ {inc['date']} {inc['title']}")

    data["incidents"].sort(key=lambda i: i["date"], reverse=True)
    data["updated"] = now
    save_json(DATA_PATH, data)
    save_json(SEEN_PATH, seen_list[-20000:])
    save_json(GEO_PATH, geo)
    print(f"done: {added} added, {merged} merged as extra sources")


if __name__ == "__main__":
    main()
