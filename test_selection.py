import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

# Tests exercise selection/storage without installing an SDK or calling services.
sys.modules.setdefault('feedparser', types.SimpleNamespace())
sys.modules.setdefault('openai', types.SimpleNamespace(OpenAI=lambda: object()))
spec = importlib.util.spec_from_file_location('updater', os.path.join(os.path.dirname(__file__), 'update.py'))
u = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = u
spec.loader.exec_module(u)

def record(**overrides):
    rec = dict(relevant=True, category='major_cyber', major_impact='essential_service_disruption',
               impact_substantiated=True, significance='Utility confirmed a water service shutdown.',
               title='Water utility disrupted', date='2026-10-25', victim='Utility', attacker='Not reported',
               what='Service shut down', ai_role='Unspecified', why='Not reported', where='No fixed location',
               geocode_query=None, duplicate_of=None, decision='include', decision_reason='Confirmed water service disruption', evidence_status='confirmed')
    rec.update(overrides)
    return rec

class SelectionTests(unittest.TestCase):
    def test_severity_tiers_depend_on_observed_impact(self):
        base=dict(context='real_world',service='unknown',reach='single',damage='unknown',essential='unknown',reason='Source evidence.')
        cases=[({},'unknown'), ({'damage':'limited'},'limited'), ({'damage':'sensitive_data'},'significant'),
               ({'reach':'multiple','damage':'sensitive_data'},'severe'),
               ({'reach':'widespread','damage':'privileged_access'},'severe'),
               ({'service':'major'},'severe'), ({'essential':'disrupted'},'severe'),
               ({'essential':'widespread_or_safety'},'critical')]
        for changes,level in cases:
            with self.subTest(changes=changes):
                self.assertEqual(u.assess_severity({**base,**changes})['level'],level)

    def test_financial_losses_do_not_require_multiple_victims(self):
        for financial,level in [('unknown','unknown'),('limited','limited'),('substantial','significant'),('major','severe')]:
            self.assertEqual(u.assess_severity(dict(context='real_world',reach='single',financial=financial))['level'],level)
        self.assertEqual(u.assess_severity(dict(context='research_only',financial='major'))['level'],'unknown')

    def test_unknown_and_test_claims_never_get_critical_glow(self):
        for context in ['unknown','research_only','unverified']:
            self.assertEqual(u.assess_severity(dict(context=context,essential='widespread_or_safety',damage='destructive'))['level'],'unknown')
        self.assertEqual(u.assess_severity()['level'],'unknown')
        self.assertEqual(u.assess_severity(dict(context='real_world',reach='widespread',damage='unknown'))['level'],'unknown')

    def test_severity_followup_preserves_supported_impact(self):
        inc={}
        u.update_severity(inc,dict(context='real_world',damage='sensitive_data',reach='single'),'https://example.org/one','2026-10-25')
        self.assertEqual(inc['severity']['level'],'significant')
        u.update_severity(inc,dict(context='unverified'),'https://example.org/rumor','2026-10-25')
        self.assertEqual(inc['severity']['source_url'],'https://example.org/one')
        u.update_severity(inc,dict(context='real_world',essential='widespread_or_safety'),'https://example.org/two','2026-10-25')
        self.assertEqual(inc['severity']['level'],'critical')
        self.assertEqual(inc['severity']['source_url'],'https://example.org/two')

    def test_severity_schema_is_strict(self):
        self.assertFalse(u.SEVERITY_SCHEMA['additionalProperties'])
        self.assertEqual(set(u.SEVERITY_SCHEMA['required']),set(u.SEVERITY_SCHEMA['properties']))

    def test_non_ai_attack_reaches_review(self):
        self.assertTrue(u.candidate_text('Ransomware shuts down a water utility'))
        self.assertTrue(u.candidate_text('Bank reports massive data theft'))
        self.assertTrue(u.candidate_text('Internet backbone compromised in cyberespionage'))
        self.assertTrue(u.candidate_text('Claude agent leaked credentials'))
        self.assertFalse(u.candidate_text('Weekly weather forecast'))

    def test_major_evidence_gate(self):
        self.assertTrue(u.eligible_record(record()))
        for changes in [dict(major_impact='none'), dict(impact_substantiated=False),
                        dict(significance='Not reported'), dict(relevant=False)]:
            self.assertFalse(u.eligible_record(record(**changes)))
        self.assertTrue(u.eligible_record(record(category='using_ai', major_impact='none', significance='Not reported')))

    def test_direct_evidence_gate_rejects_non_incidents(self):
        quote="The utility confirmed unauthorized access to its operational network."
        base=record(actual_outcome="confirmed_compromise", severity_evidence={"context":"real_world"})
        self.assertTrue(u.direct_incident_evidence(base,quote,quote))
        for outcome in ("research_demonstration","attempt_without_compromise","potential_impact_only","background_or_forecast","unverified"):
            self.assertFalse(u.direct_incident_evidence(dict(base,actual_outcome=outcome),quote,quote))
        self.assertFalse(u.direct_incident_evidence(base,quote,"Different article."))
        for passage in (
            "Successful exploitation of these vulnerabilities could allow an attacker to cause a denial of service.",
            "Two critical flaws could let a remote attacker bypass authentication or run arbitrary code.",
            "Threat actors target devices because they can provide initial access to corporate environments.",
            "The attacker attempted to exploit the server, but there was no evidence of unauthorized access.",
        ):
            self.assertFalse(u.direct_incident_evidence(base,passage,passage))
        observed = "The attackers accessed production systems and stole sensitive customer records."
        self.assertTrue(u.direct_incident_evidence(base,observed,observed))
        self.assertFalse(u.direct_incident_evidence(dict(base,major_impact="none"),quote,quote))
        self.assertFalse(u.direct_incident_evidence(dict(base,category="using_ai",ai_role="AI involvement not confirmed"),quote,quote))
        self.assertFalse(u.direct_incident_evidence(dict(base,severity_evidence={"context":"research_only"}),quote,quote))

    def test_direct_evidence_diagnostics_preserve_gate(self):
        quote = "The utility confirmed unauthorized access to its operational network."
        base = record(actual_outcome="confirmed_compromise", severity_evidence={"context":"real_world"})
        self.assertEqual(u.direct_incident_failures(base, quote, quote), [])
        self.assertEqual(u.direct_incident_failures(base, quote, "Other article"), ["verbatim_article_quote"])
        self.assertEqual(u.direct_incident_failures(dict(base, actual_outcome="research_demonstration"), quote, quote), ["confirmed_outcome"])
        self.assertEqual(u.direct_incident_failures(dict(base, impact_substantiated=False), quote, quote), ["substantiated_impact"])
        conditional = "The vulnerability could allow an attacker to access a server."
        self.assertEqual(u.direct_incident_failures(base, conditional, conditional), ["observed_outcome_wording"])
        for passage in (quote, conditional):
            self.assertEqual(u.direct_incident_evidence(base, passage, passage),
                             not u.direct_incident_failures(base, passage, passage))

    def test_direct_evidence_spelling_and_explicit_access(self):
        base=record(actual_outcome="confirmed_compromise", severity_evidence={"context":"real_world"})
        for passage in (
            "The hospital confirmed unauthorised access to patient records.",
            "Officials said an unauthorized user was able to access platform data.",
            "The hospital discovered unauthorised activity in its app, resulting in unauthorised access to patient data.",
            "This resulted in a data breach involving personal data of patients.",
        ):
            self.assertTrue(u.direct_incident_evidence(base,passage,passage))
            self.assertFalse(u.direct_incident_evidence(base,passage,"Unrelated article."))
        for passage in (
            "The flaw could allow an unauthorized user to access platform data.",
            "There was no evidence of unauthorised activity resulting in unauthorised access.",
            "The exploit might cause a data breach involving personal data.",
            "The researchers confirmed unauthorised access in a laboratory demonstration.",
        ):
            rec=base if "laboratory" not in passage else dict(base,actual_outcome="research_demonstration")
            self.assertFalse(u.direct_incident_evidence(rec,passage,passage))

    def test_explicit_confirmations_and_access_wording(self):
        base = record(actual_outcome="confirmed_compromise", severity_evidence={"context":"real_world"})
        for passage in (
            "The city can confirm it is a victim of a ransomware attack.",
            "A third party gained unauthorized access to some client tax documents.",
            "An unauthorised party had gained access to its backend management system.",
            "Ransomware encrypted data on company servers.",
        ):
            self.assertTrue(u.direct_incident_evidence(base, passage, passage))
            self.assertFalse(u.direct_incident_evidence(base, passage, "An unrelated report."))
        for passage in (
            "There was no evidence of ransomware encrypted data on company servers.",
            "The flaw could allow a third party to gain unauthorized access.",
            "The attackers attempted to gain access to the backend management system.",
            "The hypothetical scenario would cause a service outage.",
        ):
            self.assertFalse(u.direct_incident_evidence(base, passage, passage))
        quote = "A third party gained unauthorized access to some client tax documents."
        self.assertFalse(u.direct_incident_evidence(dict(base, actual_outcome="research_demonstration"), quote, quote))

    def test_third_party_and_confirmed_cyber_incident_wording(self):
        base = record(actual_outcome="confirmed_compromise", severity_evidence={"context":"real_world"})
        for passage in (
            "The hospital discovered that an unauthorized third party gained access to two employee accounts.",
            "An unauthorized third party accessed and copied files containing patient records.",
            "The agency is investigating a cybersecurity incident that resulted in unauthorized access to a limited subset of its systems.",
            "A cyber incident led to unauthorized access to operational systems.",
        ):
            self.assertTrue(u.direct_incident_evidence(base, passage, passage))
            self.assertFalse(u.direct_incident_evidence(base, passage, "Other article."))
            self.assertFalse(u.direct_incident_evidence(dict(base, impact_substantiated=False), passage, passage))
        for passage in (
            "No unauthorized third party gained access to the employee accounts.",
            "The vulnerability could allow an unauthorized third party to access records.",
            "There was no evidence of a cyber incident that resulted in unauthorized access.",
            "The incident could lead to unauthorized access to operational systems.",
            "The researchers simulated an attack in which an unauthorized third party gained access to accounts.",
        ):
            rec = dict(base, actual_outcome="research_demonstration") if "simulated" in passage else base
            self.assertFalse(u.direct_incident_evidence(rec, passage, passage))

    def test_confirmed_past_data_leak_wording(self):
        base = record(actual_outcome="confirmed_compromise", severity_evidence={"context":"real_world"})
        quote = "Personal information of customers was confirmed to have been leaked."
        self.assertTrue(u.direct_incident_evidence(base, quote, quote))
        self.assertFalse(u.direct_incident_evidence(base, quote, "Unrelated article."))
        for passage in (
            "Personal information may have been leaked.",
            "No evidence of personal information being leaked was found.",
            "The flaw could allow personal information to be leaked.",
            "The data was not confirmed to have been leaked.",
        ):
            self.assertFalse(u.direct_incident_evidence(base, passage, passage))
        self.assertFalse(u.direct_incident_evidence(dict(base, actual_outcome="research_demonstration"), quote, quote))

    def test_evidence_selection_is_exact_bounded_and_fail_closed(self):
        article = "Unrelated introduction.\nThe utility confirmed unauthorized access to its operational network.  Patient records were stolen.\nA flaw could allow access."
        spans = u.evidence_spans(article)
        base = record(actual_outcome="confirmed_compromise", severity_evidence={"context":"real_world"})
        quote = u.selected_evidence(article, spans, 2, 3)
        self.assertEqual(quote, "The utility confirmed unauthorized access to its operational network.  Patient records were stolen.")
        self.assertIn(quote, article)
        self.assertTrue(u.direct_incident_evidence(base, quote, article))
        for start, end in ((0, 0), (2, 4), (3, 2), (4, 99), (True, 2), ("2", 2)):
            self.assertEqual(u.selected_evidence(article, spans, start, end), "")
        self.assertFalse(u.direct_incident_evidence(base, u.selected_evidence(article, spans, 4, 4), article))
        self.assertFalse(u.direct_incident_evidence(dict(base, actual_outcome="research_demonstration"), quote, article))

    def test_schema_requires_all_fields(self):
        self.assertEqual(set(u.SCHEMA['required']), set(u.SCHEMA['properties']))

    def test_multiple_reported_countries_precede_vendor_fallback(self):
        inc=dict(victim='LiteLLM servers', where='United States and Western Europe', source_url='https://example.org/report')
        with patch.object(u,'geocode', side_effect=[[39,-100],[50,5]]):
            u.locate_incident(inc,{})
        self.assertEqual([p['label'] for p in inc['locations']],['United States','Western Europe'])
        self.assertTrue(all(p['basis']=='Reported affected area' for p in inc['locations']))

    def test_headquarters_is_labeled_and_sourced(self):
        inc=dict(victim='LiteLLM package pipeline', where='No fixed location', source_url='https://example.org/report')
        with patch.object(u,'geocode',return_value=[37.77,-122.42]):
            u.locate_incident(inc,{})
        self.assertIn('approximate',inc['locations'][0]['basis'])
        self.assertIn('ycombinator.com',inc['locations'][0]['source_url'])

    def test_unknown_victim_not_mapped_to_attacker_or_reporter(self):
        inc=dict(victim='Not reported', where='No fixed location', attacker='China', title='LiteLLM used by attackers', source_url='https://example.org/report')
        with patch.object(u,'geocode') as geo:
            u.locate_incident(inc,{})
        geo.assert_not_called()
        self.assertNotIn('locations',inc)

    def run_update(self, incidents, seen, items, records):
        with tempfile.TemporaryDirectory() as root:
            paths = dict(DATA_PATH=os.path.join(root,'attacks.json'), SEEN_PATH=os.path.join(root,'seen.json'), GEO_PATH=os.path.join(root,'geocache.json'))
            u.save_json(paths['DATA_PATH'], dict(incidents=incidents, updated=None))
            u.save_json(paths['SEEN_PATH'], seen)
            import coverage_collector as c
            with patch.multiple(u, **paths), patch.object(u,'ROOT',root), patch.dict(os.environ, OPENAI_API_KEY='test-only'), patch.object(c,'discover',return_value=(items,[])), patch.object(c,'read_article',return_value=('Reported source evidence','article',None)), patch.object(u,'OpenAI',side_effect=lambda **kw: object()), patch.object(u,'extract',side_effect=records), patch.object(u,'geocode',return_value=None):
                u.main()
            decisions=u.load_json(os.path.join(root,'decisions.json'),{})
            u.save_json(paths['SEEN_PATH'], [u.seen_key(i) for i in items if decisions.get(i['url'],{}).get('status') != 'error'])
            return u.load_json(paths['DATA_PATH'],{}), u.load_json(paths['SEEN_PATH'],[])

    def test_new_major_preserves_unconfirmed_label(self):
        item=dict(id='new', title='Water utility disrupted', date='2026-10-25', url='https://example.org/new', source='Test', text='')
        data, seen=self.run_update([],[],[item],[record()])
        self.assertEqual(len(data['incidents']),1)
        self.assertEqual(data['incidents'][0]['category'],'major_cyber')
        self.assertEqual(data['incidents'][0]['ai_role'],'AI involvement not confirmed in the reporting.')
        self.assertIn(u.seen_key(item), seen)

    def test_backfill_does_not_duplicate_existing_id(self):
        item=dict(id='old', title='Water utility disrupted', date='2026-10-25', url='https://example.org/old', source='Test', text='')
        existing=dict(id='old', title=item['title'], date=item['date'], victim='Utility', category='using_ai', ai_role='Reported use', source_url=item['url'])
        data, seen=self.run_update([existing],['old'],[item],[record()])
        self.assertEqual(len(data['incidents']),1)
        self.assertEqual(data['incidents'][0]['category'],'using_ai')
        self.assertIn(u.seen_key(item),seen)

    def test_later_ai_report_upgrades_existing_incident(self):
        item=dict(id='followup', title='AI role confirmed', date='2026-10-25', url='https://example.org/followup', source='Test', text='')
        existing=dict(id='old', title='Water attack', date='2026-10-24', victim='Utility', category='major_cyber', source_url='https://example.org/old')
        data, _=self.run_update([existing],[],[item],[record(category='using_ai', duplicate_of='old', ai_role='Investigators reported AI-assisted intrusion')])
        self.assertEqual(len(data['incidents']),1)
        self.assertEqual(data['incidents'][0]['category'],'using_ai')
        self.assertEqual(data['incidents'][0]['ai_source_url'],item['url'])

    def test_extraction_failure_remains_retryable(self):
        item=dict(id='retry', title='Attack', date='2026-10-25', url='https://example.org/retry', source='Test', text='')
        data, seen=self.run_update([],[],[item],[RuntimeError('test failure')])
        self.assertEqual(data['incidents'],[])
        self.assertNotIn(u.seen_key(item),seen)

if __name__ == '__main__':
    unittest.main()


