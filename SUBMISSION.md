# Mantle Smart Contract Audit Assistant

**Mantle Turing Test Hackathon 2026 — Phase 2: AI Awakening**
**Track 5: AI DevTools**

---

## What It Does

A fully local, zero-dependency CLI tool that audits Solidity smart contracts for:

1. **Security Vulnerabilities** — 25 rules covering reentrancy, access control, timestamp manipulation, and more
2. **Gas Optimization for Mantle L2** — 15 rules tuned to Mantle's two-component fee model (L1 data fee + L2 execution)
3. **ERC-8004 Compliance** — 15 rules covering all three registries of Mantle's Agent Identity NFT standard

Outputs: beautiful terminal report + standalone HTML report (no server required)

---

## Why It Matters for Mantle

Most Solidity auditors are built for Ethereum mainnet. Mantle L2 has unique characteristics that generic tools miss:

| Issue | Why Mantle-Specific |
|-------|---------------------|
| `block.timestamp` manipulation | Centralized sequencer can adjust ±15 seconds |
| Gas model | L1 data fee dominates (~90% of cost) — inverse optimization from L1 |
| MEV / front-running | Single sequencer sees all txns before inclusion |
| L2 finality | 7-day fraud proof window — premature finality assumptions cause loss |
| ERC-8004 | Mantle's own agent identity standard — no other tool checks this |

---

## Demo

```bash
# Install (2 packages only — no API key needed)
pip install click rich

# Full audit
python main.py audit contracts/vulnerable/reentrancy_example.sol

# With HTML report
python main.py audit contracts/vulnerable/reentrancy_example.sol --html report.html

# Security only
python main.py security MyContract.sol

# Gas optimization (Mantle L2 specific)
python main.py gas MyContract.sol

# ERC-8004 Agent Identity compliance
python main.py erc8004 MyAgentContract.sol

# Run all demo contracts
python main.py demo
```

---

## Sample Output

Running on `VulnerableBank.sol`:

```
Risk Level: CRITICAL
CRITICAL 2  HIGH 4  MEDIUM 2  LOW 2

[V-03] CRITICAL — Reentrancy: external call before state update (line 33)
[V-03] CRITICAL — Reentrancy: timedWithdraw (line 46)
[V-01] HIGH    — tx.origin authentication bypass (line 20)
[V-02] HIGH    — block.timestamp on Mantle L2 (±15s by sequencer) (line 41) [L2]
[V-04] HIGH    — Unprotected selfdestruct (line 69)
[V-11] HIGH    — Missing access control on emergencyWithdrawAll (line 61)
```

---

## Technical Architecture

```
main.py                    CLI (click)
src/
  engine.py                Orchestrates all rules
  parser.py                Solidity AST-like parser (pure Python, no deps)
  rules/
    base.py                Finding, Severity, RuleBase
    vulnerability_rules.py 25 security rules
    gas_rules.py           15 Mantle L2 gas rules
    erc8004_rules.py       15 ERC-8004 compliance rules
  report/
    terminal.py            Rich colored terminal output
    html_report.py         Self-contained HTML report
```

**Zero external dependencies** beyond `click` (CLI) and `rich` (terminal colors).
No API key. No network calls. Runs 100% offline.

---

## ERC-8004 Coverage

Full coverage of all three ERC-8004 registry components:

| Registry | Functions Checked | Events Checked |
|----------|------------------|----------------|
| Identity Registry | register, setAgentURI, getMetadata, setMetadata, setAgentWallet (EIP-712), getAgentWallet, unsetAgentWallet | Registered, MetadataSet |
| Reputation Registry | giveFeedback (+ owner exclusion), revokeFeedback, appendResponse, getSummary, readFeedback, readAllFeedback, getClients | NewFeedback |
| Validation Registry | validationRequest, validationResponse, getValidationStatus, getAgentValidations | ValidationResponse |

---

## Mantle L2 Gas Rules (Selected)

| Rule | Description |
|------|-------------|
| G-01 | Use `constant`/`immutable` — eliminates SLOAD, saves L1 data fee |
| G-03 | `calldata` vs `memory` for external params — saves copy + L1 bytes |
| G-06 | Custom errors vs string revert — 4 bytes vs 40+ bytes of calldata |
| G-09 | Unbounded loops — gas limit DoS risk |
| G-10 | String state vars → IPFS hash — reduces L1 posting cost |
| G-11 | `block.timestamp` in events — unnecessary L1 data on Mantle |
| G-15 | Calldata compression hints — design for Mantle DA / EigenLayer |

---

## Team

Built for Mantle Turing Test Hackathon 2026, Track 5: AI DevTools.
