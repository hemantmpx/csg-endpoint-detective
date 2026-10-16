from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from sqlalchemy.dialects import postgresql

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"backend"))
from app.main import (
    parse_search_time_range,
    search_events,
    timestamp_in_search_range,
)


class EmptyResult:
    def all(self):
        return []


class QueryCaptureSession:
    def __init__(self):
        self.statements=[]
    def scalar(self,statement):
        self.statements.append(statement)
        return 0
    def scalars(self,statement):
        self.statements.append(statement)
        return EmptyResult()
    def execute(self,statement):
        self.statements.append(statement)
        return EmptyResult()
    def add(self,value):
        pass
    def commit(self):
        pass


class EventSearchFilterTests(unittest.TestCase):
    def test_start_and_end_filter_include_bounds_and_exclude_events_outside(self):
        lower,upper=parse_search_time_range("2026-09-26T09:35:00Z","2026-09-26T09:42:00Z")
        samples=[
            ("2026-09-26T09:34:59Z",False),
            ("2026-09-26T09:35:00Z",True),
            ("2026-09-26T09:38:00Z",True),
            ("2026-09-26T09:42:00Z",True),
            ("2026-09-26T09:42:01Z",False),
        ]
        for value,expected in samples:
            with self.subTest(timestamp=value):
                self.assertEqual(timestamp_in_search_range(datetime.fromisoformat(value.replace("Z","+00:00")),lower,upper),expected)

    def test_reversed_time_range_is_rejected(self):
        with self.assertRaisesRegex(Exception,"Start time must be earlier"):
            parse_search_time_range("2026-09-26T09:42:00Z","2026-09-26T09:35:00Z")

    def test_text_and_structured_filters_are_combined_in_the_event_query(self):
        db=QueryCaptureSession()
        student=SimpleNamespace(id="student-1",variant="A")
        with patch("app.main.current_student",return_value=student), patch("app.main.assert_case_available"):
            result=search_events(
                request=SimpleNamespace(),slug="complete-state-model",q="PolicyStage.exe",
                event_type="process_start",event_category="process",event_code="1",
                provider="Microsoft-Windows-Sysmon",host="WIN-LAB-04",
                start="2026-09-26T09:35:00Z",end="2026-09-26T09:42:00Z",
                page=1,page_size=100,db=db,
            )
        self.assertEqual(result["total"],0)
        compiled=db.statements[0].compile(dialect=postgresql.dialect())
        sql=str(compiled)
        self.assertIn("events.timestamp >=",sql)
        self.assertIn("events.timestamp <=",sql)
        self.assertIn("%PolicyStage.exe%",compiled.params.values())
        for expected in ["process_start","process","1","Microsoft-Windows-Sysmon","WIN-LAB-04"]:
            self.assertIn(expected,compiled.params.values())
        self.assertTrue(compiled.params)


if __name__=="__main__":
    unittest.main()
