import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import update as u
import coverage_collector as c

class CoverageTests(unittest.TestCase):
    def test_single_report_reuses_incident_when_victim_name_is_paraphrased(self):
        from test_selection import record
        inc={'id':'canonical','title':'Cloud intrusion','date':'2026-10-20','category':'major_cyber',
             'victim':'Unnamed organization operating two cloud environments','source_url':'https://example.com/report'}
        data={'incidents':[inc]}
        item={'id':'new','url':inc['source_url'],'source':'Researcher','date':'2026-10-26','single_incident':True}
        with patch.object(u,'update_severity'):
            result,identifier=c.merge_record(u,data,item,record(victim='An unnamed cloud customer'),{},'2026-10-27T00:00:00+00:00')
        self.assertEqual((result,identifier),('merged','canonical'))
        self.assertEqual(len(data['incidents']),1)

    def test_reviewed_exclusion_reopens_only_for_changed_evidence(self):
        import hashlib
        previous={'policy':u.SELECTION_VERSION,'status':'exclude','checked':'2026-10-01T00:00:00+00:00',
                  'review_override':True,'summary_hash':hashlib.sha256(b'court recap').hexdigest()}
        now='2026-10-27T00:00:00+00:00'
        self.assertFalse(c.due({'text':'court recap'},previous,now,u.SELECTION_VERSION))
        self.assertFalse(c.due({'title':'Old court recap'},previous,now,u.SELECTION_VERSION))
        self.assertTrue(c.due({'text':'New operational incident facts'},previous,now,u.SELECTION_VERSION))

    def test_legal_rehashes_are_not_new_attacks(self):
        self.assertTrue(c.legal_followup('Snowflake Hacker Pleads Guilty in US Court'))
        self.assertTrue(c.legal_followup('Ransom Cartel Mastermind Sentenced to 16 Years in Prison'))
        self.assertFalse(c.legal_followup('Ransomware shuts down hospital care'))
        self.assertTrue(c.legal_followup('Court Sentences Ransomware Operator'))
        self.assertTrue(c.legal_followup('Strict Rules Set for Dataset in Multidistrict Litigation'))
        self.assertFalse(c.legal_followup('In Other News: Ransomware Developer Sentenced, New Attack Disclosed'))

    def test_missed_real_headlines_reach_review(self):
        for title in ['Cybersecurity Issue Forces a Major New Mexico Hospital to Divert Patients and Close Clinics',
                      'Gheist Uses Stolen GitHub Tokens to Steal Private Repository Secrets via Actions Logs',
                      'Incident de sécurité: compromissions de contrôleurs de réfrigération',
                      'Hospital system offline after security incident']:
            self.assertTrue(u.candidate_text(title), title)

    def test_changed_evidence_reopens_excluded_report(self):
        item={'text':'New victim confirmation'}
        previous={'policy':u.SELECTION_VERSION,'status':'exclude','checked':'2026-10-27T00:00:00+00:00','summary_hash':'old'}
        self.assertTrue(c.due(item, previous, '2026-10-27T01:00:00+00:00',u.SELECTION_VERSION))

    def test_unmodified_reports_do_not_repeat_every_run(self):
        import hashlib
        item={'text':'same'}
        previous={'policy':u.SELECTION_VERSION,'status':'exclude','checked':'2026-10-27T00:00:00+00:00','summary_hash':hashlib.sha256(b'same').hexdigest()}
        self.assertFalse(c.due(item,previous,'2026-10-27T01:00:00+00:00',u.SELECTION_VERSION))
        self.assertTrue(c.due(item,previous,'2026-11-04T01:00:00+00:00',u.SELECTION_VERSION))

    def test_full_article_replaces_thin_summary(self):
        item={'text':'Short feed', 'url':'https://example.com/news'}
        with patch.object(c,'download',return_value=(b'<article>body</article>',item['url'])), patch.object(c.trafilatura,'extract',return_value='Substantive facts. '*60):
            body,mode,error=c.read_article(item)
        self.assertEqual(mode,'article')
        self.assertIsNone(error)
        self.assertGreater(len(body),500)

    def test_fetch_failure_is_labeled_summary_not_full_article(self):
        with patch.object(c,'download',side_effect=ValueError('bad')):
            body,mode,error=c.read_article({'text':'snippet','url':'https://example.com/news'})
        self.assertEqual((body,mode),('snippet','summary'))
        self.assertEqual(error,'ValueError')

    def test_source_url_prevents_duplicate_with_different_id(self):
        inc={'id':'old','title':'Old','date':'2026-06-03','category':'major_cyber','victim':'Hospital','source_url':'https://example.com/event'}
        data={'incidents':[inc]}
        rec={'category':'major_cyber','what':'Confirmed new detail','evidence_status':'confirmed','geocode_query':None}
        with patch.object(u,'update_severity'):
            result,_=c.merge_record(u,data,{'id':'different','url':inc['source_url'],'source':'Hospital','date':'2026-10-26'},rec,{},'2026-10-27T00:00:00+00:00')
        self.assertEqual(result,'merged')
        self.assertEqual(len(data['incidents']),1)
        self.assertEqual(inc['date'],'2026-06-03')
        self.assertEqual(inc['last_reported'],'2026-10-26')

    def test_auth_failure_is_nonzero_and_keeps_last_success(self):
        class AuthError(Exception):
            status_code=401
        with tempfile.TemporaryDirectory() as root:
            initial={'updated':'2026-10-25T00:00:00+00:00','incidents':[]}
            Path(root,'attacks.json').write_text(json.dumps(initial))
            item={'id':'x','url':'https://example.com/news','title':'Hospital attack','source':'Test','date':'2026-10-26','text':'evidence'}
            with patch.multiple(u,ROOT=root,DATA_PATH=str(Path(root,'attacks.json')),GEO_PATH=str(Path(root,'geocache.json'))), patch.dict(c.os.environ,OPENAI_API_KEY='test'), patch.object(c,'discover',return_value=([item],[])), patch.object(c,'read_article',return_value=('facts','article',None)), patch.object(u,'OpenAI',return_value=object()), patch.object(u,'extract',side_effect=AuthError('secret-fragment-must-not-leak')):
                self.assertEqual(c.run(u),1)
            self.assertEqual(json.loads(Path(root,'attacks.json').read_text())['updated'],initial['updated'])
            status=json.loads(Path(root,'feed_status.json').read_text())
            self.assertEqual(status['status'],'failed')
            self.assertEqual(status['pending'],1)
            self.assertNotIn('secret-fragment',Path(root,'decisions.json').read_text())

    def test_private_article_urls_rejected(self):
        for url in ['http://127.0.0.1/', 'http://localhost/', 'file:///etc/passwd','http://169.254.169.254/','https://user:pass@example.com/']:
            self.assertFalse(c.public_url(url))
        self.assertTrue(c.public_url('https://www.wiz.io/blog/report'))

    def test_roundup_can_add_two_distinct_victims(self):
        from test_selection import record
        with tempfile.TemporaryDirectory() as root:
            item={'id':'roundup','url':'https://example.com/roundup','title':'Two hospital breaches','source':'Test','date':'2026-10-26','text':'facts'}
            records=[record(victim='Hospital A',title='Hospital A breach'),record(victim='Hospital B',title='Hospital B breach')]
            with patch.multiple(u,ROOT=root,DATA_PATH=str(Path(root,'attacks.json')),GEO_PATH=str(Path(root,'geocache.json'))), patch.dict(c.os.environ,OPENAI_API_KEY='test'), patch.object(c,'discover',return_value=([item],[])), patch.object(c,'read_article',return_value=('facts','article',None)), patch.object(u,'OpenAI',return_value=object()), patch.object(u,'extract',return_value=records), patch.object(u,'geocode',return_value=None):
                self.assertEqual(c.run(u),0)
            data=json.loads(Path(root,'attacks.json').read_text())
            self.assertEqual({i['victim'] for i in data['incidents']},{'Hospital A','Hospital B'})
            self.assertEqual(len({i['id'] for i in data['incidents']}),2)

    def test_roundup_new_primary_victim_does_not_overwrite_old_one(self):
        from test_selection import record
        original={'id':'roundup','title':'Hospital A','victim':'Hospital A','date':'2026-10-20','category':'major_cyber','source_url':'https://example.com/roundup'}
        data={'incidents':[original]}
        item={'id':'roundup','url':'https://example.com/roundup','source':'Test','date':'2026-10-26'}
        with patch.object(u,'geocode',return_value=None):
            result,new_id=c.merge_record(u,data,item,record(victim='Hospital B'),{},'2026-10-27T00:00:00+00:00')
        self.assertEqual(result,'added')
        self.assertNotEqual(new_id,'roundup')
        self.assertEqual(data['incidents'][0]['victim'],'Hospital A')

if __name__=='__main__':
    unittest.main()
