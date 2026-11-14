import time
from datetime import datetime, timezone

from attribution import (
    NullAttributor,
    SysmonAttributor,
    parse_sysmon_xml,
)
from models import ProcessDetails

SAMPLE_XML = """<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>11</EventID>
      <TimeCreated SystemTime="2026-11-13T10:00:01.1234567Z" />
    </System>
    <EventData>
      <Data Name="TargetFilename">C:\\lab\\_canary_01.txt</Data>
      <Data Name="ProcessId">1234</Data>
      <Data Name="UtcTime">2026-11-13 10:00:01.123</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>11</EventID>
      <TimeCreated SystemTime="2026-11-13T10:00:02.5000000Z" />
    </System>
    <EventData>
      <Data Name="TargetFilename">C:\\lab\\file1.txt</Data>
      <Data Name="ProcessId">5678</Data>
      <Data Name="UtcTime">2026-11-13 10:00:02.500</Data>
    </EventData>
  </Event>
</Events>
"""


def test_parse_sysmon_event_records():
    events = parse_sysmon_xml(SAMPLE_XML)

    assert len(events) == 2
    assert events[0].target == r"C:\lab\_canary_01.txt"
    assert events[0].pid == 1234
    assert events[0].occurred == datetime(
        2026, 11, 13, 10, 0, 1, 123000, tzinfo=timezone.utc
    )
    assert events[1].pid == 5678


def test_parse_sibling_event_roots():
    inner = SAMPLE_XML.split("<Events>", 1)[1].rsplit("</Events>", 1)[0]

    events = parse_sysmon_xml(inner)

    assert len(events) == 2


def test_parse_invalid_xml_is_empty():
    assert parse_sysmon_xml("<not xml") == []


def test_null_attributor_returns_none():
    process, method = NullAttributor().lookup(r"C:\lab\file.txt", datetime.now(timezone.utc))

    assert process is None
    assert method == "none"


def test_sysmon_lookup_matches_path_and_time(monkeypatch):
    attributor = SysmonAttributor()
    attributor._events = parse_sysmon_xml(SAMPLE_XML)
    attributor._fetched_at = time.time()

    monkeypatch.setattr(SysmonAttributor, "available", staticmethod(lambda: True))
    monkeypatch.setattr(
        attributor,
        "_describe",
        lambda pid: ProcessDetails(pid=pid, name="explorer.exe"),
    )

    process, method = attributor.lookup(
        r"C:\lab\_canary_01.txt",
        datetime(2026, 11, 13, 10, 0, 1, 200000, tzinfo=timezone.utc),
    )

    assert method == "sysmon"
    assert process is not None
    assert process.pid == 1234
    assert process.name == "explorer.exe"


def test_sysmon_lookup_outside_window_is_none(monkeypatch):
    attributor = SysmonAttributor(retry_delay=0)
    attributor._events = parse_sysmon_xml(SAMPLE_XML)
    attributor._fetched_at = time.time()

    monkeypatch.setattr(SysmonAttributor, "available", staticmethod(lambda: True))

    process, method = attributor.lookup(
        r"C:\lab\_canary_01.txt",
        datetime(2026, 11, 13, 10, 5, 0, tzinfo=timezone.utc),
    )

    assert process is None
    assert method == "none"


def test_sysmon_lookup_unknown_path_is_none(monkeypatch):
    attributor = SysmonAttributor(retry_delay=0)
    attributor._events = parse_sysmon_xml(SAMPLE_XML)
    attributor._fetched_at = time.time()

    monkeypatch.setattr(SysmonAttributor, "available", staticmethod(lambda: True))

    process, method = attributor.lookup(
        r"C:\lab\other.txt",
        datetime(2026, 11, 13, 10, 0, 1, 200000, tzinfo=timezone.utc),
    )

    assert process is None
    assert method == "none"


def test_sysmon_lookup_retries_once_for_a_late_event(monkeypatch):
    # watchdog can see the file before Sysmon writes its Event ID 11 record.
    attributor = SysmonAttributor(retry_delay=0)
    attributor._events = []
    attributor._fetched_at = time.time()

    calls = []

    def fake_recent(force=False):
        calls.append(force)
        return parse_sysmon_xml(SAMPLE_XML) if force else []

    monkeypatch.setattr(SysmonAttributor, "available", staticmethod(lambda: True))
    monkeypatch.setattr(attributor, "_recent_events", fake_recent)
    monkeypatch.setattr(
        attributor,
        "_describe",
        lambda pid: ProcessDetails(pid=pid, name="explorer.exe"),
    )

    process, method = attributor.lookup(
        r"C:\lab\file1.txt",
        datetime(2026, 11, 13, 10, 0, 2, 600000, tzinfo=timezone.utc),
    )

    assert calls == [False, True]
    assert method == "sysmon"
    assert process is not None
    assert process.pid == 5678


def test_sysmon_lookup_gives_up_after_the_retry_budget(monkeypatch):
    attributor = SysmonAttributor(retry_delay=0, retry_attempts=3)
    attributor._events = []
    attributor._fetched_at = time.time()

    calls = []

    def fake_recent(force=False):
        calls.append(force)
        return []

    monkeypatch.setattr(SysmonAttributor, "available", staticmethod(lambda: True))
    monkeypatch.setattr(attributor, "_recent_events", fake_recent)

    process, method = attributor.lookup(
        r"C:\lab\nothing.txt",
        datetime(2026, 11, 13, 10, 0, 1, 200000, tzinfo=timezone.utc),
    )

    assert calls == [False, True, True, True]
    assert process is None
    assert method == "none"
