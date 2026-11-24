import unittest
from triage_backlog import reason_for

# No-API batch triage regression checks.
class TriageTests(unittest.TestCase):
    def test_conservative_exclusions(self):
        for title in ("Annual HIPAA Summit early bird registration",
                      "Company secures $20 million in funding",
                      "Privacy Rule compliance checklist",
                      "Historic case settlement reached"):
            self.assertIsNotNone(reason_for({"title":title}))
    def test_potential_incidents_are_retained(self):
        for title in ("Old breach settlement reached", "Ransomware attack disrupts hospital",
                      "Company hacked after webinar",
                      "Supply-chain attack in new product",
                      "N-able confirms unauthorized cloud intrusion"):
            self.assertIsNone(reason_for({"title":title}))
    def test_ambiguous_headline_is_retained(self):
        self.assertIsNone(reason_for({"title":"Cloud infrastructure developments"}))

if __name__ == "__main__":
    unittest.main()
