from coverage_gate.scanner import scan_rule_file, scan_rules


def test_scans_tags_and_references(tmp_path):
    rule = tmp_path / "r.yml"
    rule.write_text("""title: Encoded PowerShell
tags:
    - attack.t1059.001
references:
    - https://attack.mitre.org/techniques/T1027/
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
""")
    got = scan_rule_file(str(rule))
    assert got.title == "Encoded PowerShell"
    assert got.category == "process_creation"
    assert "T1059.001" in got.techniques
    assert "T1027" in got.techniques


def test_directory_walk(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "a.yml").write_text("title: A\nlogsource:\n    category: process_creation\ndetection:\n    condition: selection\n")
    (d / "b.yml").write_text("title: B\nlogsource:\n    category: file_event\ndetection:\n    condition: selection\n")
    got = scan_rules([str(d)])
    assert len(got) == 2


def test_bad_file_is_reported_and_good_files_scan(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "bad.yml").write_text("{{ not yaml")
    (d / "good.yml").write_text("title: A\nlogsource:\n    category: process_creation\ndetection:\n    condition: selection\n")
    rules, errors = scan_rules([str(d)])
    assert [e[0] for e in errors] == [str(d / "bad.yml")]
    assert len(rules) == 1
