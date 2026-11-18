"""Single authorized production-model schema check; never writes briefing data."""
import json
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import briefing as b
from openai import OpenAI

reports = [{'id': 'smoke-report-1', 'source': 'Synthetic test fixture',
            'url': 'https://example.com/synthetic-test',
            'published': '2026-11-18T12:00:00Z',
            'title': 'Synthetic hospital outage fixture',
            'text': 'Fictional Example Hospital confirmed a computer outage and postponed appointments. No other facts are known. This is a synthetic test, not real news.',
            'fresh_for_overview': True, 'in_daily_window': True}]
client = OpenAI(max_retries=0, timeout=90)
response = client.chat.completions.create(
    model=os.environ.get('OPENAI_MODEL') or b.u.MODEL,
    reasoning_effort='low', max_completion_tokens=4096,
    messages=[{'role':'system','content': b.PROMPT},
              {'role':'user','content':json.dumps({'sectors_enabled':False,'prior_overviews':[], 'reports':reports})}],
    response_format={'type':'json_schema','json_schema':{'name':'daily_threat_brief','strict':True,'schema':b.source_schema(reports)}})
choice=response.choices[0]
if choice.finish_reason != 'stop' or choice.message.refusal:
    raise RuntimeError('Smoke response incomplete or refused; no retry')
value=json.loads(choice.message.content)
from jsonschema import validate
validate(value,b.source_schema(reports))
checked=b.validate(value,reports,[],False)
if not checked['overview']['items']:
    raise RuntimeError('Smoke response had no overview item; no retry')
print('PASS: one production-model call accepted constrained schema and independent validation')
print('Usage:', json.dumps(response.usage.model_dump() if response.usage else {}))
