"""Tests for JSON response parsing in analyzers."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.analyzers.vulnerability import VulnerabilityAnalyzer
from src.analyzers.gas_optimizer import GasOptimizer
from src.analyzers.erc8004 import ERC8004Checker


class MockClient:
    pass


def test_vulnerability_parser_clean_json():
    analyzer = VulnerabilityAnalyzer(MockClient())
    data = analyzer._parse_json_response('{"summary": "test", "risk_level": "LOW", "total_issues": 0, "findings": []}')
    assert data["risk_level"] == "LOW"
    assert data["total_issues"] == 0


def test_vulnerability_parser_markdown_wrapped():
    analyzer = VulnerabilityAnalyzer(MockClient())
    raw = '```json\n{"summary": "test", "risk_level": "HIGH", "total_issues": 1, "findings": []}\n```'
    data = analyzer._parse_json_response(raw)
    assert data["risk_level"] == "HIGH"


def test_vulnerability_parser_invalid_json():
    analyzer = VulnerabilityAnalyzer(MockClient())
    data = analyzer._parse_json_response("not json at all")
    assert data["risk_level"] == "UNKNOWN"
    assert "raw_response" in data


def test_gas_parser_clean_json():
    optimizer = GasOptimizer(MockClient())
    data = optimizer._parse_json_response(
        '{"summary": "good", "estimated_total_savings": "5000 gas", "optimizations": []}'
    )
    assert data["estimated_total_savings"] == "5000 gas"


def test_erc8004_parser_clean_json():
    checker = ERC8004Checker(MockClient())
    data = checker._parse_json_response(
        '{"is_compliant": false, "compliance_score": 50, "summary": "partial", '
        '"missing_features": [], "checks": [], "recommendations": []}'
    )
    assert data["compliance_score"] == 50
    assert not data["is_compliant"]
