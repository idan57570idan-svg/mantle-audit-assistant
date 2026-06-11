"""
15 gas optimization rules for Mantle L2.
Accounts for Mantle's two-component fee: L1 data fee (dominant) + L2 execution fee.
"""
import re
from typing import List
from .base import Finding, Severity, RuleBase
from ..parser import ParsedFile


# ---------------------------------------------------------------------------
# G-01: Non-immutable / non-constant state variables that could be
# ---------------------------------------------------------------------------
class ImmutableConstantRule(RuleBase):
    id = "G-01"
    title = "Use constant/immutable for Unchanging State Variables"
    severity = Severity.MEDIUM
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            for sv in contract.state_vars:
                if sv.is_constant or sv.is_immutable:
                    continue
                # Heuristic: ALL_CAPS name → should be constant
                if re.match(r'^[A-Z][A-Z0-9_]+$', sv.name) and sv.name not in ('MNT',):
                    findings.append(Finding(
                        rule_id=self.id, title=self.title, severity=self.severity,
                        lines=[sv.line],
                        description=(
                            f"State variable `{sv.name}` appears to be a constant (ALL_CAPS name) "
                            "but is not declared `constant` or `immutable`. "
                            "On Mantle L2, every SLOAD adds to L1 data costs. "
                            "Constants/immutables are embedded in bytecode — zero SLOAD cost."
                        ),
                        recommendation=(
                            f"Declare as `constant` if the value never changes: "
                            f"`{sv.type_} constant {sv.name} = ...;`\n"
                            f"Or `immutable` if set only in the constructor."
                        ),
                        code_snippet=sv.raw,
                        mantle_specific=True, category=self.category
                    ))
        return findings


# ---------------------------------------------------------------------------
# G-02: SLOAD in loop (storage read inside loop body)
# ---------------------------------------------------------------------------
class SloadInLoopRule(RuleBase):
    id = "G-02"
    title = "Storage Read (SLOAD) Inside Loop"
    severity = Severity.HIGH
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            sv_names = {sv.name for sv in contract.state_vars}
            if not sv_names:
                continue
            for fn in contract.functions:
                in_loop = False
                loop_start = 0
                depth = 0
                for abs_ln, text in fn.body_lines:
                    if re.search(r'\b(for|while)\s*\(', text):
                        in_loop = True
                        loop_start = abs_ln + 1
                        depth = text.count('{') - text.count('}')
                        continue
                    if in_loop:
                        depth += text.count('{') - text.count('}')
                        if depth <= 0:
                            in_loop = False
                            continue
                        for name in sv_names:
                            if re.search(r'\b' + re.escape(name) + r'\b', text):
                                findings.append(Finding(
                                    rule_id=self.id, title=self.title, severity=self.severity,
                                    lines=[abs_ln + 1],
                                    description=(
                                        f"State variable `{name}` is read inside a loop in `{fn.name}`. "
                                        "Each read is a costly SLOAD. On Mantle L2, this also contributes "
                                        "to L1 data fees per transaction."
                                    ),
                                    recommendation=(
                                        f"Cache `{name}` in a local variable before the loop:\n"
                                        f"`{sv.type_ if contract.state_vars else 'uint256'} cached_{name} = {name};`\n"
                                        f"Then use `cached_{name}` inside the loop."
                                    ),
                                    code_snippet=text.strip(),
                                    mantle_specific=True, category=self.category
                                ))
                                break  # one finding per loop line is enough
        return findings


# ---------------------------------------------------------------------------
# G-03: memory instead of calldata for external function params
# ---------------------------------------------------------------------------
class CalldataVsMemoryRule(RuleBase):
    id = "G-03"
    title = "Use calldata Instead of memory for External Function Parameters"
    severity = Severity.MEDIUM
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            for fn in contract.functions:
                if fn.visibility != 'external':
                    continue
                if fn.mutability in ('view', 'pure'):
                    pass  # still applies
                if re.search(r'\bmemory\b', fn.params):
                    params_with_memory = re.findall(r'([\w\[\]]+\s+memory\s+\w+)', fn.params)
                    findings.append(Finding(
                        rule_id=self.id, title=self.title, severity=self.severity,
                        lines=[fn.line],
                        description=(
                            f"External function `{fn.name}` uses `memory` for parameters "
                            f"({', '.join(params_with_memory)}). "
                            "`calldata` is read-only but avoids the memory copy overhead. "
                            "On Mantle L2, calldata parameters also appear directly in the L1 "
                            "data submission — not copying saves gas at both layers."
                        ),
                        recommendation=(
                            f"Change `memory` to `calldata` for read-only array/string/bytes parameters:\n"
                            f"`{fn.raw.replace('memory', 'calldata', 1)}`"
                        ),
                        code_snippet=fn.raw,
                        mantle_specific=True, category=self.category
                    ))
        return findings


# ---------------------------------------------------------------------------
# G-04: i++ vs ++i in loops
# ---------------------------------------------------------------------------
class PostIncrementRule(RuleBase):
    id = "G-04"
    title = "Use Pre-increment (++i) Instead of Post-increment (i++)"
    severity = Severity.LOW
    category = "gas"

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        seen = set()
        for i, line in enumerate(parsed.lines, 1):
            if re.search(r'\b\w+\+\+\b', line) and re.search(r'\bfor\b|\bwhile\b', line):
                if i not in seen:
                    seen.add(i)
                    findings.append(Finding(
                        rule_id=self.id, title=self.title, severity=self.severity,
                        lines=[i],
                        description=(
                            "Post-increment (`i++`) stores the original value before incrementing, "
                            "costing an extra copy. Pre-increment (`++i`) is ~5 gas cheaper per iteration."
                        ),
                        recommendation="Replace `i++` with `++i` in loop counters.",
                        code_snippet=line.strip(),
                        category=self.category
                    ))
        return findings


# ---------------------------------------------------------------------------
# G-05: Unnecessary zero initialization
# ---------------------------------------------------------------------------
class ZeroInitRule(RuleBase):
    id = "G-05"
    title = "Unnecessary Zero Initialization"
    severity = Severity.LOW
    category = "gas"

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for i, line in enumerate(parsed.lines, 1):
            if re.search(r'\buint\w*\s+\w+\s*=\s*0\s*;|\bbool\s+\w+\s*=\s*false\s*;', line):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[i],
                    description=(
                        "Variables are initialized to zero by default in Solidity. "
                        "Explicitly setting them to 0 wastes gas on a redundant SSTORE."
                    ),
                    recommendation="Remove the `= 0` / `= false` initialization.",
                    code_snippet=line.strip(),
                    category=self.category
                ))
        return findings


# ---------------------------------------------------------------------------
# G-06: Custom errors instead of string revert messages
# ---------------------------------------------------------------------------
class CustomErrorRule(RuleBase):
    id = "G-06"
    title = "Use Custom Errors Instead of String Revert Messages"
    severity = Severity.MEDIUM
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for i, line in enumerate(parsed.lines, 1):
            m = re.search(r'require\s*\([^,]+,\s*"([^"]{10,})"', line)
            if m:
                msg = m.group(1)
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[i],
                    description=(
                        f'String revert message "{msg[:40]}..." is stored and transmitted as calldata. '
                        "On Mantle L2, every calldata byte contributes to L1 data fees. "
                        "Custom errors cost 4 bytes for the selector vs. ~40+ bytes for strings."
                    ),
                    recommendation=(
                        f"Define a custom error: `error {msg[:20].replace(' ', '')}();`\n"
                        f"Use: `if (!condition) revert {msg[:20].replace(' ', '')}();`"
                    ),
                    code_snippet=line.strip(),
                    mantle_specific=True, category=self.category
                ))
        return findings


# ---------------------------------------------------------------------------
# G-07: Struct packing — storage slot optimization
# ---------------------------------------------------------------------------
class StoragePackingRule(RuleBase):
    id = "G-07"
    title = "Storage Slot Packing Opportunity"
    severity = Severity.MEDIUM
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            consecutive_smalls: List[int] = []
            for sv in contract.state_vars:
                is_small = re.match(r'^(uint(?:8|16|24|32|48|64|72|80|88|96|104|112|120|128)|bool|address)', sv.type_)
                if is_small:
                    consecutive_smalls.append(sv.line)
                else:
                    consecutive_smalls = []
                if len(consecutive_smalls) >= 3:
                    findings.append(Finding(
                        rule_id=self.id, title=self.title, severity=self.severity,
                        lines=consecutive_smalls[-3:],
                        description=(
                            f"Contract `{contract.name}` has multiple small state variables "
                            "that could be packed into fewer storage slots. "
                            "Each storage slot is 32 bytes. Packing reduces SSTORE/SLOAD count, "
                            "which on Mantle L2 also reduces L1 data posting costs."
                        ),
                        recommendation=(
                            "Group small variables together and use a struct:\n"
                            "```solidity\nstruct Config {\n    uint128 value1;\n    uint64 value2;\n    uint64 value3;\n}\nConfig public config;\n```"
                        ),
                        code_snippet=f"# {len(consecutive_smalls)} small vars in {contract.name}",
                        mantle_specific=True, category=self.category
                    ))
                    consecutive_smalls = []
        return findings


# ---------------------------------------------------------------------------
# G-08: Redundant duplicate storage reads in same function
# ---------------------------------------------------------------------------
class RedundantSloadRule(RuleBase):
    id = "G-08"
    title = "Redundant Storage Reads in Same Function"
    severity = Severity.MEDIUM
    category = "gas"

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            sv_names = {sv.name for sv in contract.state_vars}
            for fn in contract.functions:
                read_count: dict = {}
                for abs_ln, text in fn.body_lines:
                    for name in sv_names:
                        if re.search(r'\b' + re.escape(name) + r'\b', text):
                            read_count[name] = read_count.get(name, 0) + 1
                for name, count in read_count.items():
                    if count >= 3:
                        findings.append(Finding(
                            rule_id=self.id, title=self.title, severity=self.severity,
                            lines=[fn.line],
                            description=(
                                f"State variable `{name}` is read {count} times in `{fn.name}`. "
                                "Each read is a SLOAD (~100-2100 gas). Cache it in a local variable."
                            ),
                            recommendation=(
                                f"Add at the top of `{fn.name}`:\n"
                                f"`uint256 cached_{name} = {name};`\n"
                                f"Then replace all reads of `{name}` with `cached_{name}`."
                            ),
                            code_snippet=f"# {name} read {count}x in {fn.name}",
                            category=self.category
                        ))
        return findings


# ---------------------------------------------------------------------------
# G-09: Unbounded loop over dynamic array
# ---------------------------------------------------------------------------
class UnboundedLoopRule(RuleBase):
    id = "G-09"
    title = "Unbounded Loop Over Dynamic Array"
    severity = Severity.HIGH
    category = "gas"

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            # Find dynamic array state vars
            dynamic_arrays = {
                sv.name for sv in contract.state_vars
                if re.search(r'\[\s*\]', sv.type_) or re.search(r'^(\w+)\[\]$', sv.type_)
            }
            for fn in contract.functions:
                for abs_ln, text in fn.body_lines:
                    m = re.search(r'for\s*\([^;]*;\s*\w+\s*<\s*(\w+)\.length', text)
                    if m:
                        arr_name = m.group(1)
                        if arr_name in dynamic_arrays or True:
                            findings.append(Finding(
                                rule_id=self.id, title=self.title, severity=self.severity,
                                lines=[abs_ln + 1],
                                description=(
                                    f"Loop over dynamic array `{arr_name}.length` in `{fn.name}`. "
                                    "If the array grows unboundedly, this function will eventually "
                                    "exceed the block gas limit and become permanently uncallable."
                                ),
                                recommendation=(
                                    "Implement pagination: add `offset` and `limit` parameters. "
                                    "Or use EnumerableSet from OpenZeppelin which supports efficient "
                                    "iteration. Cap array growth with a MAX_SIZE check."
                                ),
                                code_snippet=text.strip(),
                                category=self.category
                            ))
        return findings


# ---------------------------------------------------------------------------
# G-10: string/bytes in public state variables (L1 data cost on Mantle)
# ---------------------------------------------------------------------------
class StringStateVarRule(RuleBase):
    id = "G-10"
    title = "String/Bytes Public State Variable — High L1 Data Cost on Mantle"
    severity = Severity.MEDIUM
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            for sv in contract.state_vars:
                if re.match(r'^(string|bytes)\s', sv.type_) and sv.visibility == 'public':
                    findings.append(Finding(
                        rule_id=self.id, title=self.title, severity=self.severity,
                        lines=[sv.line],
                        description=(
                            f"Public `string/bytes` state variable `{sv.name}` is stored on-chain. "
                            "On Mantle L2, large strings significantly increase L1 data posting costs. "
                            "String data in state also contributes to L1 calldata for every transaction "
                            "that modifies it."
                        ),
                        recommendation=(
                            "Store large strings off-chain (IPFS) and keep only the hash on-chain: "
                            f"`bytes32 public {sv.name}Hash;`\n"
                            "Or use `bytes32` for fixed-size strings (up to 32 chars)."
                        ),
                        code_snippet=sv.raw,
                        mantle_specific=True, category=self.category
                    ))
        return findings


# ---------------------------------------------------------------------------
# G-11: Emit event with timestamp — extra L1 calldata on Mantle
# ---------------------------------------------------------------------------
class EventTimestampRule(RuleBase):
    id = "G-11"
    title = "Block.timestamp in Event — Unnecessary L1 Data Cost"
    severity = Severity.LOW
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for i, line in enumerate(parsed.lines, 1):
            if re.search(r'\bemit\b.*block\.timestamp', line):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[i],
                    description=(
                        "Emitting `block.timestamp` in an event adds 32 bytes to L1 calldata "
                        "on Mantle L2. The timestamp is already available from the block data "
                        "and does not need to be stored in the event."
                    ),
                    recommendation=(
                        "Remove `block.timestamp` from the event. "
                        "Clients can read the block timestamp from the block header directly."
                    ),
                    code_snippet=line.strip(),
                    mantle_specific=True, category=self.category
                ))
        return findings


# ---------------------------------------------------------------------------
# G-12: Boolean comparison to literal
# ---------------------------------------------------------------------------
class BoolLiteralRule(RuleBase):
    id = "G-12"
    title = "Comparison to Boolean Literal"
    severity = Severity.LOW
    category = "gas"

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for i, line in enumerate(parsed.lines, 1):
            if re.search(r'==\s*true\b|==\s*false\b|!=\s*true\b|!=\s*false\b', line):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[i],
                    description="Comparing a boolean expression to `true`/`false` wastes gas.",
                    recommendation=(
                        "Use the boolean directly: `if (flag)` instead of `if (flag == true)`. "
                        "Use `!flag` instead of `flag == false`."
                    ),
                    code_snippet=line.strip(),
                    category=self.category
                ))
        return findings


# ---------------------------------------------------------------------------
# G-13: Multiple SSTORE in sequence — pack into struct
# ---------------------------------------------------------------------------
class MultipleSSstoreRule(RuleBase):
    id = "G-13"
    title = "Multiple Sequential SSTOREs — Consider Struct Packing"
    severity = Severity.MEDIUM
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            sv_names = {sv.name for sv in contract.state_vars}
            for fn in contract.functions:
                consecutive_writes = 0
                write_start = 0
                prev_abs_ln = 0
                for abs_ln, text in fn.body_lines:
                    has_write = any(
                        re.search(r'\b' + re.escape(n) + r'\s*=', text) for n in sv_names
                    )
                    if has_write:
                        if consecutive_writes == 0:
                            write_start = abs_ln + 1
                        consecutive_writes += 1
                    else:
                        if consecutive_writes >= 4:
                            findings.append(Finding(
                                rule_id=self.id, title=self.title, severity=self.severity,
                                lines=list(range(write_start, write_start + consecutive_writes)),
                                description=(
                                    f"Function `{fn.name}` writes to {consecutive_writes} separate state "
                                    "variables in sequence, each costing an SSTORE (~20,000 gas cold). "
                                    "On Mantle L2, each SSTORE also adds to L1 data fee."
                                ),
                                recommendation=(
                                    "Group related variables into a single struct. "
                                    "Writing a struct costs one SSTORE per slot instead of N SSTOREs. "
                                    "Pack small types together to minimize storage slots."
                                ),
                                code_snippet=f"# {consecutive_writes} sequential SSTOREs in {fn.name}",
                                mantle_specific=True, category=self.category
                            ))
                        consecutive_writes = 0
        return findings


# ---------------------------------------------------------------------------
# G-14: address(this).balance in loop or repeated
# ---------------------------------------------------------------------------
class BalanceInLoopRule(RuleBase):
    id = "G-14"
    title = "address(this).balance in Loop or Used Multiple Times"
    severity = Severity.LOW
    category = "gas"

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            for fn in contract.functions:
                count = sum(
                    1 for _, text in fn.body_lines
                    if re.search(r'address\s*\(\s*this\s*\)\s*\.balance', text)
                )
                if count >= 2:
                    findings.append(Finding(
                        rule_id=self.id, title=self.title, severity=self.severity,
                        lines=[fn.line],
                        description=(
                            f"`address(this).balance` is read {count} times in `{fn.name}`. "
                            "Each read is a BALANCE opcode (~400 gas). Cache it once."
                        ),
                        recommendation=(
                            "Cache at function start:\n`uint256 contractBalance = address(this).balance;`"
                        ),
                        code_snippet=f"# balance read {count}x in {fn.name}",
                        category=self.category
                    ))
        return findings


# ---------------------------------------------------------------------------
# G-15: Mantle — use EIP-1559 type 2 tx pattern (calldata compression hint)
# ---------------------------------------------------------------------------
class CalldataCompressionHintRule(RuleBase):
    id = "G-15"
    title = "Calldata Compression Hint — Optimize for Mantle L1 Data Fee"
    severity = Severity.INFO
    category = "gas"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            for fn in contract.functions:
                if fn.visibility not in ('public', 'external'):
                    continue
                # Count non-address, non-uint256 params
                complex_params = re.findall(
                    r'(bytes(?:\d+)?\s+\w+|string\s+\w+|struct\s+\w+)',
                    fn.params
                )
                if len(complex_params) >= 2:
                    findings.append(Finding(
                        rule_id=self.id, title=self.title, severity=self.severity,
                        lines=[fn.line],
                        description=(
                            f"Function `{fn.name}` has {len(complex_params)} complex calldata parameters. "
                            "On Mantle L2, all calldata is compressed and posted to Ethereum L1 "
                            "(or Mantle DA via EigenLayer). Zero bytes cost 4 gas, non-zero 16 gas in L1 calldata. "
                            "Designing data to be zero-byte-rich improves compression ratio."
                        ),
                        recommendation=(
                            "• Pad small integers to predictable sizes (easier compression)\n"
                            "• Use ABI-encoded structs — zeros in padding compress well\n"
                            "• Consider off-chain data with on-chain hash commitment for large blobs\n"
                            "• Use Mantle DA for data-heavy applications (30-70% cheaper than L1)"
                        ),
                        code_snippet=fn.raw,
                        mantle_specific=True, category=self.category
                    ))
        return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
ALL_GAS_RULES: List[RuleBase] = [
    ImmutableConstantRule(),
    SloadInLoopRule(),
    CalldataVsMemoryRule(),
    PostIncrementRule(),
    ZeroInitRule(),
    CustomErrorRule(),
    StoragePackingRule(),
    RedundantSloadRule(),
    UnboundedLoopRule(),
    StringStateVarRule(),
    EventTimestampRule(),
    BoolLiteralRule(),
    MultipleSSstoreRule(),
    BalanceInLoopRule(),
    CalldataCompressionHintRule(),
]
