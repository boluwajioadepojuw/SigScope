"""Self-contained ATT&CK fixture for tests (no network, deterministic)."""

ATTACK_FIXTURE = {
    "version": "test-fixture-1.0",
    "tactics": {
        "execution": {"id": "TA0002", "name": "Execution", "shortname": "execution", "url": "https://attack.mitre.org/tactics/TA0002"},
        "persistence": {"id": "TA0003", "name": "Persistence", "shortname": "persistence", "url": "https://attack.mitre.org/tactics/TA0003"},
        "privilege-escalation": {"id": "TA0004", "name": "Privilege Escalation", "shortname": "privilege-escalation", "url": "https://attack.mitre.org/tactics/TA0004"},
        # NOTE: no explicit "id" on purpose — exercises the URL-parsing fallback.
        "credential-access": {"name": "Credential Access", "shortname": "credential-access", "url": "https://attack.mitre.org/tactics/TA0006"},
    },
    "techniques": {
        "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "url": "https://attack.mitre.org/techniques/T1059", "tactics": ["execution"], "is_subtechnique": False},
        "T1059.001": {"id": "T1059.001", "name": "PowerShell", "url": "https://attack.mitre.org/techniques/T1059/001", "tactics": ["execution"], "is_subtechnique": True},
        "T1053.005": {"id": "T1053.005", "name": "Scheduled Task", "url": "https://attack.mitre.org/techniques/T1053/005", "tactics": ["persistence", "privilege-escalation"], "is_subtechnique": True},
        "T1505.003": {"id": "T1505.003", "name": "Web Shell", "url": "https://attack.mitre.org/techniques/T1505/003", "tactics": ["persistence"], "is_subtechnique": True},
        "T1003": {"id": "T1003", "name": "OS Credential Dumping", "url": "https://attack.mitre.org/techniques/T1003", "tactics": ["credential-access"], "is_subtechnique": False},
    },
}
