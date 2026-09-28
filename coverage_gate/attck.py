"""Small curated ATT&CK snapshot used as the coverage map.

Not the full matrix on purpose: the tool answers the question for the
techniques a small SOC actually writes rules about. Extend the dicts below
when the rule set grows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Technique:
    id: str
    name: str
    tactic: str


_TACTICS = [
    "RECONNAISSANCE", "RESOURCE_DEVELOPMENT", "INITIAL_ACCESS", "EXECUTION",
    "PERSISTENCE", "PRIVILEGE_ESCALATION", "DEFENSE_EVASION",
    "CREDENTIAL_ACCESS", "DISCOVERY", "LATERAL_MOVEMENT", "COLLECTION",
    "COMMAND_AND_CONTROL", "EXFILTRATION", "IMPACT",
]

_TECHNIQUES: List[Technique] = [
    Technique("T1059", "Command and Scripting Interpreter", "EXECUTION"),
    Technique("T1059.001", "PowerShell", "EXECUTION"),
    Technique("T1059.003", "Windows Command Shell", "EXECUTION"),
    Technique("T1059.004", "Unix Shell", "EXECUTION"),
    Technique("T1106", "Native API", "EXECUTION"),
    Technique("T1204", "User Execution", "EXECUTION"),
    Technique("T1204.002", "Malicious File", "EXECUTION"),
    Technique("T1053", "Scheduled Task/Job", "PERSISTENCE"),
    Technique("T1053.005", "Scheduled Task", "PERSISTENCE"),
    Technique("T1547", "Boot or Logon Autostart Execution", "PERSISTENCE"),
    Technique("T1547.001", "Registry Run Keys / Startup Folder", "PERSISTENCE"),
    Technique("T1136", "Create Account", "PERSISTENCE"),
    Technique("T1136.001", "Local Account", "PERSISTENCE"),
    Technique("T1078", "Valid Accounts", "PERSISTENCE"),
    Technique("T1218", "System Binary Proxy Execution", "DEFENSE_EVASION"),
    Technique("T1218.003", "CMSTP", "DEFENSE_EVASION"),
    Technique("T1218.005", "Mshta", "DEFENSE_EVASION"),
    Technique("T1027", "Obfuscated Files or Information", "DEFENSE_EVASION"),
    Technique("T1036", "Masquerading", "DEFENSE_EVASION"),
    Technique("T1562", "Impair Defenses", "DEFENSE_EVASION"),
    Technique("T1562.001", "Disable or Modify Tools", "DEFENSE_EVASION"),
    Technique("T1055", "Process Injection", "DEFENSE_EVASION"),
    Technique("T1112", "Modify Registry", "DEFENSE_EVASION"),
    Technique("T1003", "OS Credential Dumping", "CREDENTIAL_ACCESS"),
    Technique("T1003.001", "LSASS Memory", "CREDENTIAL_ACCESS"),
    Technique("T1082", "System Information Discovery", "DISCOVERY"),
    Technique("T1033", "System Owner/User Discovery", "DISCOVERY"),
    Technique("T1016", "System Network Configuration Discovery", "DISCOVERY"),
    Technique("T1018", "Remote System Discovery", "DISCOVERY"),
    Technique("T1057", "Process Discovery", "DISCOVERY"),
    Technique("T1049", "System Network Connections Discovery", "DISCOVERY"),
    Technique("T1012", "Query Registry", "DISCOVERY"),
    Technique("T1046", "Network Service Discovery", "DISCOVERY"),
    Technique("T1135", "Network Share Discovery", "DISCOVERY"),
    Technique("T1021", "Remote Services", "LATERAL_MOVEMENT"),
    Technique("T1021.001", "Remote Desktop Protocol", "LATERAL_MOVEMENT"),
    Technique("T1021.002", "SMB/Windows Admin Shares", "LATERAL_MOVEMENT"),
    Technique("T1560", "Archive Collected Data", "COLLECTION"),
    Technique("T1560.001", "Archive via Utility", "COLLECTION"),
    Technique("T1071", "Application Layer Protocol", "COMMAND_AND_CONTROL"),
    Technique("T1071.001", "Web Protocols", "COMMAND_AND_CONTROL"),
    Technique("T1571", "Non-Standard Port", "COMMAND_AND_CONTROL"),
    Technique("T1041", "Exfiltration Over C2 Channel", "EXFILTRATION"),
    Technique("T1190", "Exploit Public-Facing Application", "INITIAL_ACCESS"),
    Technique("T1566", "Phishing", "INITIAL_ACCESS"),
    Technique("T1566.001", "Spearphishing Attachment", "INITIAL_ACCESS"),
    Technique("T1595", "Active Scanning", "RECONNAISSANCE"),
    Technique("T1583", "Acquire Infrastructure", "RESOURCE_DEVELOPMENT"),
    Technique("T1485", "Data Destruction", "IMPACT"),
    Technique("T1498", "Network Denial of Service", "IMPACT"),
    Technique("T1548", "Abuse Elevation Control Mechanism", "PRIVILEGE_ESCALATION"),
    Technique("T1548.002", "Bypass User Account Control", "PRIVILEGE_ESCALATION"),
    Technique("T1505", "Server Software Component", "PERSISTENCE"),
    Technique("T1505.003", "Web Shell", "PERSISTENCE"),
]


@dataclass
class AttackMap:
    techniques: Dict[str, Technique] = field(default_factory=dict)
    tactics: List[str] = field(default_factory=lambda: list(_TACTICS))

    @classmethod
    def build(cls, overrides: Optional[Dict] = None) -> "AttackMap":
        m = cls()
        for t in _TECHNIQUES:
            m.techniques[t.id] = t
        if overrides:
            for tid, data in overrides.items():
                m.techniques[tid] = Technique(tid, data.get("name", tid), data.get("tactic", "EXECUTION"))
        return m

    def lookup(self, tid: str) -> Optional[Technique]:
        if tid in self.techniques:
            return self.techniques[tid]
        return None

    def tactic_of(self, tid: str) -> str:
        t = self.lookup(tid)
        return t.tactic if t else "UNKNOWN"

    def children_of(self, tid: str) -> List[str]:
        return sorted(k for k in self.techniques if k.startswith(tid + "."))
