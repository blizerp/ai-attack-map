import copy
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import briefing as b

NOW = datetime(2026,10,27,21,tzinfo=timezone.utc)

def report(**values):
    return dict(id='r1',url='https://example.com/story',title='Hospital systems disrupted',source='Example',
                date='2026-10-27',published_at='2026-10-27T18:00:00+00:00',text='The hospital confirmed an outage.',
                evidence='article',fingerprint='first',**values)

def result():
    item={'headline':'Hospital services disrupted','what_happened':'A hospital confirmed a computer outage.',
          'impact':'Some appointments were postponed.','what_next':'The hospital has not given a recovery date.',
          'change':'New report','sectors':['healthcare'],'source_ids':['r1']}
    return {'overview':{'intro':'Hospital patients face delays.','items':[item]},
            'sectors':{s:{'intro':'','items':[copy.deepcopy(item)] if s=='healthcare' else []} for s in b.SECTORS}}

class BriefingTests(unittest.TestCase):
    def test_schedule_dst_and_delayed_execution(self):
        for stamp, expected in [('2026-07-01T12:35:00+00:00',12),('2026-12-01T13:35:00+00:00',13)]:
            _,kind,target=b.edition_slot(b.parse(stamp),'0 8 * * *')
            self.assertEqual(kind,'morning');self.assertEqual(target.astimezone(timezone.utc).hour,expected)
        date,kind,_=b.edition_slot(b.parse('2026-10-28T01:00:00+00:00'),'0 17 * * *')
        self.assertEqual((date,kind),('2026-10-27','evening'))

    def test_windows_continue_after_actual_morning_collection(self):
        previous=[{'window_end':'2026-10-27T12:20:00+00:00'}]
        start,daily=b.windows(NOW,'evening',previous)
        self.assertEqual(start,b.parse(previous[0]['window_end']))
        self.assertEqual(daily,NOW-timedelta(days=1))

    def test_evening_does_not_repeat_unchanged_reports_but_sector_keeps_them(self):
        r=report(); seen={r['url']:{'fingerprint':'first'}}
        reports=b.prepare([r],NOW-timedelta(hours=9),NOW-timedelta(days=1),seen,True)
        self.assertFalse(reports[0]['fresh_for_overview'])
        self.assertTrue(reports[0]['in_daily_window'])
        self.assertEqual(b.prepare([r],NOW-timedelta(hours=9),NOW-timedelta(days=1),seen,False),[])
        r['fingerprint']='changed'
        self.assertTrue(b.prepare([r],NOW-timedelta(hours=9),NOW-timedelta(days=1),seen,False)[0]['fresh_for_overview'])

    def test_old_backfill_does_not_become_fresh_news(self):
        r=report();r.update(date='2026-10-01',published_at='2026-10-01T12:00:00Z')
        self.assertEqual(b.prepare([r],NOW-timedelta(hours=9),NOW-timedelta(days=1),{},True),[])

    def test_source_validation_and_mapping(self):
        reports=b.prepare([report()],NOW-timedelta(hours=9),NOW-timedelta(days=1),{},True)
        value=result();value['overview']['items'][0]['headline']='Example Regional Hospital services disrupted'
        validated=b.validate(value,reports,[{'id':'map1','victim':'Example Regional Hospital','source_url':report()['url']}],True)
        self.assertEqual(validated['overview']['items'][0]['incident_ids'],['map1'])
        bad=result();bad['overview']['items'][0]['source_ids']=['invented']
        with self.assertRaises(ValueError):b.validate(bad,reports,[],True)
        reports[0]['fresh_for_overview']=False
        with self.assertRaises(ValueError):b.validate(result(),reports,[],True)

    def test_failure_keeps_previous_edition_and_retry_is_possible(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{'BRIEF_SCHEDULE':'','BRIEF_EDITION':'auto'}):
            root=Path(tmp); prior={'id':'old','date':'2026-10-26','published_at':'2026-10-26T21:00:00+00:00','window_end':'2026-10-26T21:00:00+00:00','overview':{'items':[]}}
            b.atomic(root/'briefings.json',{'editions':[prior]})
            def failed(*args):raise RuntimeError('unavailable')
            self.assertEqual(b.run(root,NOW,client=object(),gatherer=failed),1)
            data=json.loads((root/'briefings.json').read_text())
            self.assertEqual(data['editions'],[prior]);self.assertEqual(data['last_attempt']['status'],'failed')
            self.assertFalse((root/'brief_state.json').exists())

    def test_valid_publish_archive_and_no_second_api_call(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{'BRIEF_SCHEDULE':'','BRIEF_EDITION':'evening'}):
            root=Path(tmp)
            response=SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content=json.dumps(result()),refusal=None))],usage=None)
            create=unittest.mock.Mock(return_value=response)
            client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
            gather=lambda *args:([report()],[{'source':'Example','ok':True}],0)
            self.assertEqual(b.run(root,NOW,client,gather),0)
            self.assertEqual(b.run(root,NOW,client,gather),0)
            self.assertEqual(create.call_count,1)
            saved=json.loads((root/'briefings.json').read_text())['editions'][0]
            self.assertEqual(saved['edition'],'evening');self.assertTrue(saved['sectors_enabled'])
            self.assertNotIn('text',(root/'brief_state.json').read_text())

    def test_editorial_replacement_keeps_window_and_failed_replacement_keeps_content(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{'BRIEF_SCHEDULE':'','BRIEF_EDITION':'auto','BRIEF_REPLACE_LATEST':'false'}):
            root=Path(tmp)
            response=SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content=json.dumps(result()),refusal=None))],usage=None)
            create=unittest.mock.Mock(return_value=response)
            client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
            gather=lambda *args:([report()],[{'source':'Example','ok':True}],0)
            self.assertEqual(b.run(root,NOW,client,gather),0)
            original=json.loads((root/'briefings.json').read_text())['editions'][0]
            os.environ['BRIEF_REPLACE_LATEST']='true'
            self.assertEqual(b.run(root,NOW+timedelta(minutes=20),client,gather),0)
            current=json.loads((root/'briefings.json').read_text())['editions']
            self.assertEqual(len(current),1)
            self.assertEqual(current[0]['window_end'],original['window_end'])
            self.assertEqual(create.call_count,2)
            create.side_effect=RuntimeError('failed replacement')
            self.assertEqual(b.run(root,NOW+timedelta(minutes=30),client,gather),1)
            self.assertEqual(json.loads((root/'briefings.json').read_text())['editions'],current)

    def test_generic_online_store_does_not_imply_food_sector(self):
        item={'sectors':['internet','food','water','energy']}
        b.ground_sector_tags(item,[{'title':'953 online stores hacked','text':'Shoppers encountered malicious browser code.'}])
        self.assertEqual(item['sectors'],['internet'])
        item={'sectors':['food']}
        b.ground_sector_tags(item,[{'title':'Food distributor attack','text':'Food deliveries were delayed.'}])
        self.assertEqual(item['sectors'],['food'])

    def test_roundup_link_does_not_point_at_another_victim(self):
        item={'headline':'Denver Health data exposed','what_happened':'Denver Health vendor key exposed.'}
        self.assertEqual(b.matching_incidents(item,[{'id':'wrong','victim':'Johns Hopkins Bayview Medical Center'}, {'id':'right','victim':'Denver Health Medical Plan'}]),['right'])

    def test_morning_has_no_sector_rewrite(self):
        reports=b.prepare([report()],NOW-timedelta(hours=9),NOW-timedelta(days=1),{},False)
        value=b.validate(result(),reports,[],False)
        self.assertTrue(all(not s['items'] for s in value['sectors'].values()))

if __name__=='__main__':unittest.main()
