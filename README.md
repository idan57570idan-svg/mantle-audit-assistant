# Mantle Smart Contract Audit Assistant

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-8%20passed-brightgreen)
![Rules](https://img.shields.io/badge/rules-55%20total-orange)
![No API Key](https://img.shields.io/badge/API%20key-not%20required-brightgreen)

**Fully local, zero-dependency Solidity auditor built for Mantle L2.**  
25 security rules · 15 Mantle L2 gas rules · 15 ERC-8004 compliance rules · HTML reports

*Mantle Turing Test Hackathon 2026 — Track 5: AI DevTools*

</div>

---

## Why Mantle-Specific?

Most Solidity auditors are trained on Ethereum mainnet patterns. Mantle L2 has unique properties that generic tools miss entirely:

| Issue | Ethereum L1 | Mantle L2 | This Tool |
|-------|------------|-----------|-----------|
| `block.timestamp` | Miner can shift ~15s | Centralized sequencer — adjustable | **Flags as HIGH/L2** |
| Gas model | Storage cheap, calldata costly | L1 data fee dominates (~90%) | **Inverted optimization rules** |
| MEV risk | Mempool competition | Single sequencer sees all txns | **Flags sandwich-prone patterns** |
| Finality | ~12s block time | 7-day fraud proof window | **Flags premature finality logic** |
| ERC-8004 | N/A | Mantle Agent Identity NFT standard | **15 compliance rules** |

---

## Features

### Security Analysis — 25 Rules

| ID | Severity | Rule | Mantle L2 |
|----|----------|------|-----------|
| V-01 | HIGH | `tx.origin` authentication bypass | |
| V-02 | HIGH | `block.timestamp` manipulation | **L2** |
| V-03 | CRITICAL | Reentrancy (Checks-Effects-Interactions) | |
| V-04 | CRITICAL | Unprotected `selfdestruct` | |
| V-05 | HIGH | Unsafe `delegatecall` | |
| V-06 | MEDIUM | Unchecked low-level call return | |
| V-07 | MEDIUM | Unsafe integer casting | |
| V-08 | LOW | Floating pragma version | |
| V-09 | LOW | Missing zero-address validation | |
| V-10 | HIGH | Weak on-chain randomness | **L2** |
| V-11 | HIGH | Missing access control on critical functions | |
| V-12 | HIGH | Signature replay attack | |
| V-15 | HIGH | L2 finality assumption / premature settlement | **L2** |
| V-16 | MEDIUM | Front-running / MEV exposure | **L2** |
| V-18 | MEDIUM | Centralization risk (single owner) | |
| V-19 | MEDIUM | Flash loan attack surface | |
| V-20 | MEDIUM | Unchecked arithmetic block | |
| V-24 | MEDIUM | Division before multiplication (precision loss) | |
| V-25 | HIGH | Missing cross-chain message validation | **L2** |
| ... | ... | + 6 more rules | |

### Gas Optimization — 15 Rules (Mantle L2 Tuned)

> **Key insight:** On Mantle L2, the L1 data posting fee dominates (~90% of total tx cost). This means optimization priorities are *inverted* compared to Ethereum mainnet — prefer storage over calldata, minimize calldata bytes, use Mantle DA for large data.

| ID | Impact | Rule |
|----|--------|------|
| G-01 | MEDIUM | Use `constant`/`immutable` — eliminates SLOAD, saves L1 data fee |
| G-02 | HIGH | SLOAD inside loops — cache storage vars before loop |
| G-03 | MEDIUM | `calldata` instead of `memory` for external params |
| G-06 | MEDIUM | Custom errors vs string messages — 4 bytes vs 40+ in calldata |
| G-07 | MEDIUM | Struct packing for storage slot optimization |
| G-09 | HIGH | Unbounded loop over dynamic array — gas DoS risk |
| G-10 | MEDIUM | `string` public state vars → IPFS hash (saves L1 data cost) |
| G-11 | LOW | `block.timestamp` in events — unnecessary L1 data |
| G-15 | INFO | Calldata compression hints for Mantle DA / EigenLayer |
| ... | ... | + 6 more rules |

### ERC-8004 Compliance — 15 Rules

ERC-8004 is Mantle's **Agent Identity NFT standard** (deployed mainnet February 2026), enabling trustless on-chain identity for AI agents. The standard has three registry components:

```
ERC-8004
├── Identity Registry (ERC-721 extension)
│   ├── register(agentURI, metadata[]) → tokenId
│   ├── setAgentURI / getMetadata / setMetadata
│   └── setAgentWallet (EIP-712 signed) / getAgentWallet / unsetAgentWallet
├── Reputation Registry
│   ├── giveFeedback (submitter != owner enforced)
│   ├── revokeFeedback / appendResponse
│   └── getSummary / readFeedback / readAllFeedback / getClients
└── Validation Registry
    ├── validationRequest / validationResponse
    └── getValidationStatus / getAgentValidations
```

This tool checks all 15 required functions, 5 required events, EIP-712 signatures, and the owner-exclusion constraint on feedback.

---

## Quick Start

```bash
# Clone and install (2 packages only — no API key needed)
git clone https://github.com/your-repo/mantle-audit-assistant
cd mantle-audit-assistant
pip install click rich

# Full audit (terminal + HTML report)
python main.py audit MyContract.sol --html report.html

# Security vulnerabilities only
python main.py security MyContract.sol

# Gas optimization for Mantle L2
python main.py gas MyContract.sol

# ERC-8004 Agent Identity NFT compliance
python main.py erc8004 MyAgentContract.sol

# Run demo on all sample contracts
python main.py demo
```

---

## Sample Output

Running `python main.py audit contracts/vulnerable/reentrancy_example.sol`:

```
╔═══════════ [ Mantle Smart Contract Audit Assistant ] ════════════╗
║  File:      reentrancy_example.sol                               ║
║  Risk Level:  ■ ■ ■ ■ ■  CRITICAL                               ║
║  CRITICAL 2  HIGH 4  MEDIUM 2  LOW 2  INFO 0                     ║
╚══════════════════════════════════════════════════════════════════╝

  ID     Severity    Title                                  Line   L2
  V-03   CRITICAL    Reentrancy Vulnerability                 33
  V-03   CRITICAL    Reentrancy Vulnerability                 46
  V-01   HIGH        tx.origin Authentication Bypass          20
  V-02   HIGH        Block Timestamp Manipulation (L2)        41    L2
  V-04   HIGH        Unprotected selfdestruct                 69
  V-11   HIGH        Missing Access Control                   61

╔═══════════════════════ Summary ══════════════════════════════════╗
║  Security Risk:      CRITICAL  (2C / 4H / 2M / 2L)              ║
║  Gas Optimizations:  5 found  (4 high/medium impact)             ║
║  ERC-8004 Score:     0/100    (15 issues)                        ║
╚══════════════════════════════════════════════════════════════════╝
✓ HTML report saved: report.html
```

---

## Architecture

```
mantle-audit-assistant/
├── main.py                      # CLI entry point (click)
├── requirements.txt             # click, rich — nothing else
│
├── src/
│   ├── engine.py                # Orchestrates all 55 rules
│   ├── parser.py                # Solidity AST-like parser (pure Python)
│   ├── rules/
│   │   ├── base.py              # Finding, Severity, RuleBase
│   │   ├── vulnerability_rules.py  # 25 security rules
│   │   ├── gas_rules.py            # 15 Mantle L2 gas rules
│   │   └── erc8004_rules.py        # 15 ERC-8004 compliance rules
│   └── report/
│       ├── terminal.py          # Rich colored terminal output
│       └── html_report.py       # Self-contained HTML report
│
├── contracts/vulnerable/        # Sample contracts for testing
│   ├── reentrancy_example.sol   # Triggers V-01, V-02, V-03, V-04, V-11...
│   ├── gas_wasteful.sol         # Triggers G-02, G-03, G-09, G-11...
│   └── erc8004_incomplete.sol   # Triggers E-01 through E-15
│
└── tests/
    └── test_engine.py           # 8 unit tests (all passing)
```

**Zero external AI API dependencies.** The intelligence is embedded in the rules themselves — built by AI, runs without AI.

---

## HTML Report

The `--html` flag generates a single self-contained HTML file:

- **Dark theme** — professional security audit aesthetic
- **Summary cards** — risk level, gas findings, ERC-8004 compliance score
- **Sortable finding tables** — click any row to expand full details
- **ERC-8004 compliance ring** — visual score from 0–100
- **Fully offline** — no CDN, no external requests, just open in any browser

---

## Running Tests

```bash
python -m pytest tests/ -v
# 8 passed in 0.19s
```

---

## Requirements

- Python 3.10+
- `click>=8.1.0`
- `rich>=13.0.0`
- No API keys. No internet connection required.

---

## License

MIT — free to use, fork, and extend.

---

<div align="center">

Built for **Mantle Turing Test Hackathon 2026** · Track 5: AI DevTools

*Static analysis engine · Fully local · 55 rules · No API required*

</div>
