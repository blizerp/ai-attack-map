import tempfile
import unittest
from pathlib import Path
from build_site import build


class SiteTests(unittest.TestCase):
    def test_publishes_current_data_and_revision_without_source_frontmatter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath('index.html').write_text('---\nlayout: null\n---\n<meta name="site-revision" content="{{ site.github.build_revision }}">')
            root.joinpath('attacks.json').write_text('{"incidents":[]}')
            root.joinpath('briefings.json').write_text('{"editions":[]}')
            root.joinpath('briefing.js').write_text('// briefing UI')
            root.joinpath('briefing.css').write_text('/* briefing styles */')
            root.joinpath('brief_state.json').write_text('{"seen":{}}')
            root.joinpath('feed_status.json').write_text('{"status":"failed"}')
            root.joinpath('private-test.env').write_text('never publish arbitrary files')
            out = root / '_site'
            build(root, 'a' * 40, out)
            self.assertNotIn('---', out.joinpath('index.html').read_text())
            self.assertIn('a' * 40, out.joinpath('index.html').read_text())
            self.assertEqual(out.joinpath('attacks.json').read_text(), '{"incidents":[]}')
            self.assertIn('failed', out.joinpath('feed_status.json').read_text())
            self.assertFalse(out.joinpath('private-test.env').exists())
            self.assertTrue(out.joinpath('briefings.json').exists())
            self.assertTrue(out.joinpath('briefing.js').exists())
            self.assertTrue(out.joinpath('briefing.css').exists())
            self.assertFalse(out.joinpath('brief_state.json').exists())


if __name__ == '__main__':
    unittest.main()
