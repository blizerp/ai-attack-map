import copy
import unittest
from unittest.mock import Mock
from types import SimpleNamespace
import jsonschema
import briefing as b
from test_briefing import result

class SourceSchemaTests(unittest.TestCase):
    def test_every_section_rejects_unknown_and_empty_ids(self):
        schema=b.source_schema([{'id':'r1'}])
        for section in ['overview', *b.SECTORS]:
            for ids in [[], ['invented']]:
                value=result()
                item=copy.deepcopy(value['overview']['items'][0]);item['source_ids']=ids
                target=value['overview'] if section=='overview' else value['sectors'][section]
                target['items']=[item]
                with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(value,schema)
        jsonschema.validate(result(),schema)

    def test_schema_is_per_call_and_global_is_unchanged(self):
        original=copy.deepcopy(b.SCHEMA)
        a=b.source_schema([{'id':'r1'},{'id':'r1'}]); other=b.source_schema([{'id':'r2'}])
        self.assertEqual(b.SCHEMA,original)
        jsonschema.validate(result(),a)
        with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(result(),other)
        with self.assertRaises(ValueError):b.source_schema([])

    def test_empty_candidates_make_no_api_call(self):
        client=Mock()
        value,usage=b.generate(client,[],[],False,[])
        client.chat.completions.create.assert_not_called()
        self.assertEqual(value['overview']['items'],[])

    def test_api_receives_constrained_schema_and_validator_still_rejects(self):
        import json
        client=Mock()
        bad=result();bad['overview']['items'][0]['source_ids']=['invented']
        response=SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(refusal=None,content=json.dumps(bad)),finish_reason='stop')])
        client.chat.completions.create.return_value=response
        with self.assertRaises(ValueError):b.generate(client,[{'id':'r1'}],[],True,[])
        self.assertEqual(client.chat.completions.create.call_count,2)
        schema=client.chat.completions.create.call_args.kwargs['response_format']['json_schema']['schema']
        with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(bad,schema)
