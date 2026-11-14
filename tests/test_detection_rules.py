from pathlib import Path

from detection_rules import (
    CANARY_FILES,
    DetectionRules,
)

TRIGGER = 1_000_000.0


def rules(**overrides):
    return DetectionRules(**overrides)


def test_normal_file_raises_no_alert():
    detector = rules()

    result = detector.process_event("MODIFIED", r"C:\lab\testdata\normal1.txt", now=TRIGGER)

    assert result.accepted
    assert result.alerts == ()
    assert result.event_count == 1


def test_canary_file_raises_critical_alert():
    detector = rules()

    result = detector.process_event("MODIFIED", r"C:\lab\testdata\_canary_02.txt", now=TRIGGER)

    assert result.accepted
    assert len(result.alerts) == 1

    alert = result.alerts[0]

    assert alert.severity == "Critical"
    assert alert.summary == r"Canary file detected: C:\lab\testdata\_canary_02.txt"
    assert alert.event_type == "MODIFIED"


def test_canary_match_is_case_insensitive():
    detector = rules()

    result = detector.process_event("CREATED", r"C:\lab\testdata\_CANARY_03.TXT", now=TRIGGER)

    assert [alert.severity for alert in result.alerts] == ["Critical"]


def test_all_three_canaries_are_known():
    assert CANARY_FILES == {"_canary_01.txt", "_canary_02.txt", "_canary_03.txt"}


def test_duplicate_canary_events_are_debounced():
    """One file operation can emit CREATED + MODIFIED; it must alert once."""

    detector = rules()

    first = detector.process_event("CREATED", r"C:\lab\testdata\_canary_01.txt", now=TRIGGER)
    second = detector.process_event("MODIFIED", r"C:\lab\testdata\_canary_01.txt", now=TRIGGER + 0.1)
    third = detector.process_event("MODIFIED", r"C:\lab\testdata\_canary_01.txt", now=TRIGGER + 0.4)

    assert [alert.severity for alert in first.alerts] == ["Critical"]
    assert second.accepted is False
    assert second.alerts == ()
    assert third.accepted is False
    assert detector.event_count == 1


def test_canary_alerts_again_after_debounce_window():
    detector = rules()

    detector.process_event("MODIFIED", r"C:\lab\testdata\_canary_01.txt", now=TRIGGER)
    later = detector.process_event("MODIFIED", r"C:\lab\testdata\_canary_01.txt", now=TRIGGER + 1.0)

    assert later.accepted
    assert [alert.severity for alert in later.alerts] == ["Critical"]


def test_mass_change_below_threshold_is_silent():
    detector = rules()

    results = [
        detector.process_event("CREATED", rf"C:\lab\testdata\file{index}.txt", now=TRIGGER + index)
        for index in range(9)
    ]

    assert all(result.alerts == () for result in results)
    assert results[-1].event_count == 9


def test_mass_change_alert_at_threshold():
    detector = rules()

    results = [
        detector.process_event("CREATED", rf"C:\lab\testdata\file{index}.txt", now=TRIGGER + index * 0.1)
        for index in range(10)
    ]

    assert results[-1].event_count == 10
    assert len(results[-1].alerts) == 1

    alert = results[-1].alerts[0]

    assert alert.severity == "High"
    assert alert.summary == "Mass-change detected: 10 events in 10 seconds"


def test_mass_change_cooldown_suppresses_repeat_alerts():
    detector = rules(rate_threshold=3, alert_cooldown_seconds=5)

    first = detector.process_event("CREATED", r"C:\lab\testdata\a.txt", now=TRIGGER)
    second = detector.process_event("CREATED", r"C:\lab\testdata\b.txt", now=TRIGGER + 1)
    third = detector.process_event("CREATED", r"C:\lab\testdata\c.txt", now=TRIGGER + 2)
    fourth = detector.process_event("CREATED", r"C:\lab\testdata\d.txt", now=TRIGGER + 4)
    fifth = detector.process_event("CREATED", r"C:\lab\testdata\e.txt", now=TRIGGER + 7)

    assert first.alerts == () and second.alerts == ()
    assert [alert.severity for alert in third.alerts] == ["High"]
    assert fourth.alerts == ()          # inside the cooldown
    assert [alert.severity for alert in fifth.alerts] == ["High"]


def test_events_leave_the_rolling_window():
    detector = rules(rate_threshold=3, rate_window_seconds=10)

    for index in range(2):
        detector.process_event("CREATED", rf"C:\lab\testdata\old{index}.txt", now=TRIGGER + index)

    # Two fresh events, far after the old ones: the window is empty again.
    result = detector.process_event("CREATED", r"C:\lab\testdata\new.txt", now=TRIGGER + 100)

    assert result.event_count == 1
    assert result.alerts == ()


def test_debounce_is_per_file():
    detector = rules()

    first = detector.process_event("MODIFIED", r"C:\lab\testdata\a.txt", now=TRIGGER)
    second = detector.process_event("MODIFIED", r"C:\lab\testdata\b.txt", now=TRIGGER + 0.1)

    assert first.accepted and second.accepted
    assert second.event_count == 2


def test_rename_counts_as_one_window_event():
    """A rename emits MOVED + MOVED_TO; only the source may count."""

    detector = rules(rate_threshold=2)

    source = detector.process_event("MOVED", r"C:\lab\testdata\old.txt", now=TRIGGER)
    destination = detector.process_event(
        "MOVED_TO",
        r"C:\lab\testdata\new.txt",
        now=TRIGGER + 0.001,
        count_event=False,
    )

    assert source.accepted and destination.accepted
    assert detector.event_count == 1
    assert destination.alerts == ()


def test_rename_destination_still_triggers_canary():
    detector = rules()

    detector.process_event("MOVED", r"C:\lab\testdata\plain.txt", now=TRIGGER)

    result = detector.process_event(
        "MOVED_TO",
        r"C:\lab\testdata\_canary_01.txt",
        now=TRIGGER + 0.001,
        count_event=False,
    )

    assert [alert.rule for alert in result.alerts] == ["canary"]
    assert detector.event_count == 1


def test_directory_events_are_ignored(tmp_path: Path):
    detector = rules()

    result = detector.process_event("CREATED", str(tmp_path), now=TRIGGER)

    assert result.accepted is False
    assert result.alerts == ()
    assert detector.event_count == 0
