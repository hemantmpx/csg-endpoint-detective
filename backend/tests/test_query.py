import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.main import parse_query
from fastapi import HTTPException

class QueryParserTests(unittest.TestCase):
    def test_field_and_quoted_terms(self):
        ast=parse_query('event.type:service_modified AND service.name:"UpdateHelper"')
        self.assertEqual(ast[0],"and")
        self.assertEqual(ast[1],("term","event.type","service_modified"))
        self.assertEqual(ast[2],("term","service.name","UpdateHelper"))

    def test_or_precedence(self):
        ast=parse_query('event.id:7040 OR event.id:7045 AND host.name:WIN-LAB-01')
        self.assertEqual(ast[0],"or")
        self.assertEqual(ast[2][0],"and")

    def test_free_text(self):
        self.assertEqual(parse_query('powershell.exe'),("term","_text","powershell.exe"))

    def test_unknown_fields_are_rejected(self):
        with self.assertRaises(HTTPException): parse_query('secret.field:value')

    def test_incomplete_expression_is_rejected(self):
        with self.assertRaises(HTTPException): parse_query('event.id:7040 AND')

if __name__=="__main__": unittest.main()
