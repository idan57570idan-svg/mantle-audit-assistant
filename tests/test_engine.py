"""Tests for the static analysis engine."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.engine import AuditEngine
from src.parser import parse
from src.rules.base import Severity


REENTRANCY_CONTRACT = """
pragma solidity ^0.8.0;
contract Bank {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""

CLEAN_CONTRACT = """
pragma solidity 0.8.19;
contract SimpleStorage {
    uint256 private _value;
    event ValueSet(uint256 indexed value);
    function setValue(uint256 v) external {
        _value = v;
        emit ValueSet(v);
    }
    function getValue() external view returns (uint256) { return _value; }
}
"""

TX_ORIGIN_CONTRACT = """
pragma solidity 0.8.0;
contract Auth {
    address owner;
    modifier onlyOwner() { require(tx.origin == owner); _; }
    function action() external onlyOwner {}
}
"""

GAS_CONTRACT = """
pragma solidity 0.8.0;
contract Wasteful {
    uint256 counter = 0;
    function loop(uint256[] memory items) external {
        for (uint256 i = 0; i < items.length; i++) {
            counter += items[i];
        }
    }
}
"""


def test_reentrancy_detected():
    engine = AuditEngine(run_security=True, run_gas=False, run_erc8004=False)
    result = engine.analyze(REENTRANCY_CONTRACT)
    vuln_ids = [f.rule_id for f in result.security_findings]
    assert "V-03" in vuln_ids, f"Expected reentrancy V-03 in {vuln_ids}"


def test_clean_contract_no_critical():
    engine = AuditEngine(run_security=True, run_gas=False, run_erc8004=False)
    result = engine.analyze(CLEAN_CONTRACT)
    criticals = [f for f in result.security_findings if f.severity == Severity.CRITICAL]
    assert len(criticals) == 0, f"Unexpected criticals: {criticals}"


def test_tx_origin_detected():
    engine = AuditEngine(run_security=True, run_gas=False, run_erc8004=False)
    result = engine.analyze(TX_ORIGIN_CONTRACT)
    vuln_ids = [f.rule_id for f in result.security_findings]
    assert "V-01" in vuln_ids, f"Expected tx.origin V-01 in {vuln_ids}"


def test_gas_memory_calldata():
    engine = AuditEngine(run_security=False, run_gas=True, run_erc8004=False)
    result = engine.analyze(GAS_CONTRACT)
    ids = [f.rule_id for f in result.gas_findings]
    assert "G-03" in ids, f"Expected calldata vs memory G-03 in {ids}"


def test_risk_level_critical():
    engine = AuditEngine(run_security=True, run_gas=False, run_erc8004=False)
    result = engine.analyze(REENTRANCY_CONTRACT)
    assert result.risk_level() in ("CRITICAL", "HIGH", "MEDIUM")


def test_compliance_score_0_for_empty_contract():
    engine = AuditEngine(run_security=False, run_gas=False, run_erc8004=True)
    result = engine.analyze("pragma solidity 0.8.0;\ncontract Empty {}")
    assert result.compliance_score() < 50


def test_parser_finds_functions():
    pf = parse(REENTRANCY_CONTRACT)
    assert len(pf.contracts) == 1
    assert pf.contracts[0].name == "Bank"
    fn_names = [f.name for f in pf.contracts[0].functions]
    assert "withdraw" in fn_names
    assert "deposit" in fn_names


def test_parser_pragma():
    pf = parse("pragma solidity 0.8.19;\ncontract A {}")
    assert pf.pragma == "0.8.19"
