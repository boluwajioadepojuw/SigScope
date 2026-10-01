from coverage_gate.cli import main

RULE = '''title: Test rule
owner: lab
id: 00000000-0000-4000-8000-000000000001
status: experimental
description: Fixture rule
references:
    - https://attack.mitre.org/techniques/T1059/004/
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\cmd.exe'
    condition: selection
level: low
'''


def _write_rule(tmp_path):
    d = tmp_path / 'r'
    d.mkdir()
    p = d / 't.yml'
    p.write_text(RULE)
    return str(p)


def test_min_coverage_pass(tmp_path):
    rule = _write_rule(tmp_path)
    assert main([rule, '--min-coverage', '1', '--quiet']) == 0


def test_min_coverage_fail_exits_2(tmp_path):
    rule = _write_rule(tmp_path)
    assert main([rule, '--min-coverage', '99', '--quiet']) == 2


def test_csv_output(tmp_path):
    rule = _write_rule(tmp_path)
    csv_path = tmp_path / 'out.csv'
    rc = main([rule, '--csv', str(csv_path), '--quiet'])
    assert rc == 0
    content = csv_path.read_text()
    assert 'technique_id' in content
    assert 'T1059.004' in content


def test_csv_has_technique_name(tmp_path):
    rule = _write_rule(tmp_path)
    csv_path = tmp_path / 'out2.csv'
    main([rule, '--csv', str(csv_path), '--quiet'])
    assert 'Unix Shell' in csv_path.read_text()


def test_gap_workbook_has_uncovered(tmp_path):
    rule = _write_rule(tmp_path)
    gaps_path = tmp_path / 'gaps.md'
    rc = main([rule, '--gaps', str(gaps_path), '--quiet'])
    assert rc == 0
    content = gaps_path.read_text()
    assert 'coverage workbook' in content
    assert 'no rule yet' in content


def test_gap_workbook_next_actions(tmp_path):
    rule = _write_rule(tmp_path)
    gaps_path = tmp_path / 'gaps2.md'
    main([rule, '--gaps', str(gaps_path), '--quiet'])
    assert 'Next actions' in gaps_path.read_text()


def test_bad_rule_warns_but_passes_without_strict(tmp_path):
    bad = tmp_path / 'bad.yml'
    bad.write_text('{{ not yaml')
    good = _write_rule(tmp_path)
    assert main([str(bad), good, '--quiet']) == 0


def test_bad_rule_fails_with_strict(tmp_path):
    bad = tmp_path / 'bad.yml'
    bad.write_text('{{ not yaml')
    good = _write_rule(tmp_path)
    assert main([str(bad), good, '--strict', '--quiet']) == 1


def test_navigator_output(tmp_path):
    rule = _write_rule(tmp_path)
    layer_path = tmp_path / 'layer.json'
    rc = main([rule, '--navigator', str(layer_path), '--quiet'])
    assert rc == 0
    import json
    layer = json.loads(layer_path.read_text())
    assert layer['domain'] == 'enterprise-attack'
    assert any(t['techniqueID'] == 'T1059.004' for t in layer['techniques'])


def test_min_tactic_coverage_pass(tmp_path):
    rule = _write_rule(tmp_path)
    assert main([rule, '--include', 'execution', '--min-tactic-coverage', '1', '--quiet']) == 0


def test_comma_separated_include_tokens(tmp_path):
    rule = _write_rule(tmp_path)
    assert main([rule, '--include', 'execution,T1059.004', '--min-tactic-coverage', '1', '--quiet']) == 0


def test_min_tactic_coverage_fail_exits_2(tmp_path):
    rule = _write_rule(tmp_path)
    assert main([rule, '--include', 'execution', '--min-tactic-coverage', '90', '--quiet']) == 2
