"""
Analysis engine — orchestrates all rules on a parsed contract.
"""
from dataclasses import dataclass, field
from typing import List, Dict
from .parser import ParsedFile, parse
from .rules.base import Finding, Severity
from .rules.vulnerability_rules import ALL_VULNERABILITY_RULES
from .rules.gas_rules import ALL_GAS_RULES
from .rules.erc8004_rules import ALL_ERC8004_RULES


@dataclass
class AuditResult:
    source_file: str
    parsed: ParsedFile
    security_findings: List[Finding] = field(default_factory=list)
    gas_findings: List[Finding] = field(default_factory=list)
    compliance_findings: List[Finding] = field(default_factory=list)

    # ── summary helpers ───────────────────────────────────────────────────

    def all_findings(self) -> List[Finding]:
        return self.security_findings + self.gas_findings + self.compliance_findings

    def risk_level(self) -> str:
        if any(f.severity == Severity.CRITICAL for f in self.security_findings):
            return "CRITICAL"
        if any(f.severity == Severity.HIGH for f in self.security_findings):
            return "HIGH"
        if any(f.severity == Severity.MEDIUM for f in self.security_findings):
            return "MEDIUM"
        if self.security_findings:
            return "LOW"
        return "SAFE"

    def risk_color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "SAFE": "bold green",
        }[self.risk_level()]

    def compliance_score(self) -> int:
        """0-100 ERC-8004 compliance score."""
        total = len(ALL_ERC8004_RULES)
        if total == 0:
            return 100
        critical_fail = sum(
            1 for f in self.compliance_findings if f.severity == Severity.CRITICAL
        )
        high_fail = sum(
            1 for f in self.compliance_findings if f.severity == Severity.HIGH
        )
        med_fail = sum(
            1 for f in self.compliance_findings if f.severity == Severity.MEDIUM
        )
        penalty = critical_fail * 15 + high_fail * 8 + med_fail * 3
        return max(0, 100 - penalty)

    def severity_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.security_findings:
            counts[f.severity.name] += 1
        return counts

    def gas_impact_counts(self) -> Dict[str, int]:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.gas_findings:
            counts[f.severity.name] += 1
        return counts


class AuditEngine:
    def __init__(self, run_security=True, run_gas=True, run_erc8004=True):
        self.run_security = run_security
        self.run_gas = run_gas
        self.run_erc8004 = run_erc8004

    def analyze_file(self, filepath: str) -> AuditResult:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
        return self.analyze(source, filepath)

    def analyze(self, source: str, label: str = "<input>") -> AuditResult:
        parsed = parse(source)
        result = AuditResult(source_file=label, parsed=parsed)

        if self.run_security:
            for rule in ALL_VULNERABILITY_RULES:
                try:
                    result.security_findings.extend(rule.check(parsed))
                except Exception:
                    pass

        if self.run_gas:
            for rule in ALL_GAS_RULES:
                try:
                    result.gas_findings.extend(rule.check(parsed))
                except Exception:
                    pass

        if self.run_erc8004:
            for rule in ALL_ERC8004_RULES:
                try:
                    result.compliance_findings.extend(rule.check(parsed))
                except Exception:
                    pass

        # Sort by severity (highest first)
        sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        result.security_findings.sort(key=lambda f: sev_order.index(f.severity))
        result.gas_findings.sort(key=lambda f: sev_order.index(f.severity))
        result.compliance_findings.sort(key=lambda f: sev_order.index(f.severity))

        return result
