"""
ERC-8004 compliance rules — Mantle Agent Identity NFT standard.
Three registry components: Identity, Reputation, Validation.
"""
import re
from typing import List
from .base import Finding, Severity, RuleBase
from ..parser import ParsedFile


def _has_function(contract, name_pattern: str) -> bool:
    pat = re.compile(name_pattern, re.IGNORECASE)
    return any(pat.search(fn.name) for fn in contract.functions)


def _has_event(contract, name_pattern: str) -> bool:
    pat = re.compile(name_pattern, re.IGNORECASE)
    return any(pat.search(ev.name) for ev in contract.events)


def _body_all(contract) -> str:
    return "\n".join(
        "\n".join(t for _, t in fn.body_lines)
        for fn in contract.functions
    )


# ── Identity Registry ──────────────────────────────────────────────────────

class E01_RegisterFunction(RuleBase):
    id = "E-01"
    title = "ERC-8004: Missing register() Function"
    severity = Severity.CRITICAL
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_function(contract, r'^register$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing the required `register()` function. "
                        "ERC-8004 Identity Registry MUST provide: "
                        "`register(string agentURI, MetadataEntry[] metadata) returns (uint256)`"
                    ),
                    recommendation=(
                        "Implement:\n"
                        "```solidity\nfunction register(\n"
                        "    string calldata agentURI,\n"
                        "    MetadataEntry[] calldata metadata\n"
                        ") external returns (uint256 agentId) {\n"
                        "    agentId = ++_tokenIdCounter;\n"
                        "    _mint(msg.sender, agentId);\n"
                        "    _agentURIs[agentId] = agentURI;\n"
                        "    emit Registered(agentId, msg.sender, agentURI);\n"
                        "}\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E02_SetAgentURI(RuleBase):
    id = "E-02"
    title = "ERC-8004: Missing setAgentURI() Function"
    severity = Severity.HIGH
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_function(contract, r'^setAgentURI$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Missing `setAgentURI(uint256 agentId, string newURI)` in `{contract.name}`. "
                        "Agents must be able to update their metadata URI."
                    ),
                    recommendation=(
                        "```solidity\nfunction setAgentURI(uint256 agentId, string calldata newURI) external {\n"
                        "    require(ownerOf(agentId) == msg.sender, \"Not owner\");\n"
                        "    _agentURIs[agentId] = newURI;\n"
                        "    emit MetadataSet(agentId, \"agentURI\", bytes(newURI));\n"
                        "}\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E03_GetMetadata(RuleBase):
    id = "E-03"
    title = "ERC-8004: Missing getMetadata() Function"
    severity = Severity.HIGH
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_function(contract, r'^getMetadata$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Missing `getMetadata(uint256 agentId, string key) returns (bytes)` "
                        f"in `{contract.name}`."
                    ),
                    recommendation=(
                        "```solidity\nfunction getMetadata(uint256 agentId, string calldata key)\n"
                        "    external view returns (bytes memory) {\n"
                        "    return _metadata[agentId][key];\n"
                        "}\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E04_SetMetadata(RuleBase):
    id = "E-04"
    title = "ERC-8004: Missing setMetadata() Function"
    severity = Severity.HIGH
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_function(contract, r'^setMetadata$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Missing `setMetadata(uint256 agentId, string key, bytes value)` "
                        f"in `{contract.name}`."
                    ),
                    recommendation=(
                        "```solidity\nfunction setMetadata(\n"
                        "    uint256 agentId, string calldata key, bytes calldata value\n"
                        ") external {\n"
                        "    require(ownerOf(agentId) == msg.sender, \"Not owner\");\n"
                        "    _metadata[agentId][key] = value;\n"
                        "    emit MetadataSet(agentId, key, value);\n"
                        "}\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E05_SetAgentWallet(RuleBase):
    id = "E-05"
    title = "ERC-8004: Missing setAgentWallet() with EIP-712 Signature"
    severity = Severity.HIGH
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            fn = next((f for f in contract.functions if f.name == 'setAgentWallet'), None)
            if not fn:
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Missing `setAgentWallet()` in `{contract.name}`. "
                        "ERC-8004 requires EIP-712 signed wallet changes with a deadline."
                    ),
                    recommendation=(
                        "```solidity\nfunction setAgentWallet(\n"
                        "    uint256 agentId, address newWallet,\n"
                        "    uint256 deadline, bytes calldata signature\n"
                        ") external {\n"
                        "    require(block.timestamp <= deadline, \"Expired\");\n"
                        "    bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(\n"
                        "        WALLET_TYPEHASH, agentId, newWallet, deadline\n"
                        "    )));\n"
                        "    require(ECDSA.recover(hash, signature) == ownerOf(agentId));\n"
                        "    _agentWallets[agentId] = newWallet;\n"
                        "}\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
            else:
                body = fn.body_text()
                if not re.search(r'deadline|signature|ECDSA|_hashTypedDataV4|EIP712', body):
                    findings.append(Finding(
                        rule_id=self.id,
                        title="ERC-8004: setAgentWallet() Missing EIP-712 Signature Verification",
                        severity=Severity.HIGH,
                        lines=[fn.line],
                        description=(
                            "`setAgentWallet()` exists but lacks EIP-712 signature verification. "
                            "Any owner can change the wallet without cryptographic proof."
                        ),
                        recommendation=(
                            "Add EIP-712 typed data signing: inherit `EIP712` from OpenZeppelin "
                            "and use `_hashTypedDataV4` + `ECDSA.recover` to verify the signature."
                        ),
                        code_snippet=fn.raw,
                        mantle_specific=True, category=self.category
                    ))
        return findings


class E06_AgentWalletGetUnset(RuleBase):
    id = "E-06"
    title = "ERC-8004: Missing getAgentWallet() or unsetAgentWallet()"
    severity = Severity.MEDIUM
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            missing = []
            if not _has_function(contract, r'^getAgentWallet$'):
                missing.append('getAgentWallet(uint256 agentId) returns (address)')
            if not _has_function(contract, r'^unsetAgentWallet$'):
                missing.append('unsetAgentWallet(uint256 agentId)')
            if missing:
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing: {', '.join(missing)}"
                    ),
                    recommendation=(
                        "Implement both functions to complete the wallet management interface."
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E07_RegisteredEvent(RuleBase):
    id = "E-07"
    title = "ERC-8004: Missing Registered Event"
    severity = Severity.HIGH
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            has_event = _has_event(contract, r'^(Registered|AgentRegistered)$')
            if not has_event:
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing the `Registered` event. "
                        "ERC-8004 MUST emit: "
                        "`event Registered(uint256 indexed agentId, address indexed owner, string agentURI)`"
                    ),
                    recommendation=(
                        "```solidity\nevent Registered(\n"
                        "    uint256 indexed agentId,\n"
                        "    address indexed owner,\n"
                        "    string agentURI\n"
                        ");\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E08_MetadataSetEvent(RuleBase):
    id = "E-08"
    title = "ERC-8004: Missing MetadataSet Event"
    severity = Severity.MEDIUM
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_event(contract, r'^MetadataSet$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing the `MetadataSet` event. "
                        "Required: `event MetadataSet(uint256 indexed agentId, string key, bytes value)`"
                    ),
                    recommendation=(
                        "```solidity\nevent MetadataSet(\n"
                        "    uint256 indexed agentId,\n"
                        "    string key,\n"
                        "    bytes value\n"
                        ");\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E09_ERC721Inheritance(RuleBase):
    id = "E-09"
    title = "ERC-8004: Not Inheriting ERC-721"
    severity = Severity.CRITICAL
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        erc721_pats = [r'ERC721', r'IERC721']
        for contract in parsed.contracts:
            if contract.kind in ('interface',):
                continue
            has_erc721 = any(
                any(re.search(p, inh) for p in erc721_pats)
                for inh in contract.inheritance
            )
            # Also check if all required ERC-721 functions are implemented
            has_balance_of = _has_function(contract, r'^balanceOf$')
            has_owner_of = _has_function(contract, r'^ownerOf$')
            if not has_erc721 and not (has_balance_of and has_owner_of):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` does not inherit ERC-721. "
                        "ERC-8004 Agent Identity tokens MUST implement the full ERC-721 interface."
                    ),
                    recommendation=(
                        "Inherit OpenZeppelin ERC721:\n"
                        "```solidity\nimport \"@openzeppelin/contracts/token/ERC721/ERC721.sol\";\n"
                        "contract AgentRegistry is ERC721 {\n"
                        "    constructor() ERC721(\"AgentIdentity\", \"AID\") {}\n"
                        "}\n```"
                    ),
                    code_snippet=f"contract {contract.name} is {', '.join(contract.inheritance) or '(none)'}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E10_SupportsInterface(RuleBase):
    id = "E-10"
    title = "ERC-8004: Missing supportsInterface() (ERC-165)"
    severity = Severity.MEDIUM
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_function(contract, r'^supportsInterface$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` does not implement `supportsInterface()`. "
                        "ERC-165 is required for ERC-8004 to signal interface compatibility to other contracts."
                    ),
                    recommendation=(
                        "Override supportsInterface:\n"
                        "```solidity\nfunction supportsInterface(bytes4 interfaceId)\n"
                        "    public view override returns (bool) {\n"
                        "    return interfaceId == type(IAgentIdentity).interfaceId\n"
                        "        || super.supportsInterface(interfaceId);\n"
                        "}\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


# ── Reputation Registry ────────────────────────────────────────────────────

class E11_GiveFeedback(RuleBase):
    id = "E-11"
    title = "ERC-8004: Missing Reputation Registry — giveFeedback()"
    severity = Severity.HIGH
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_function(contract, r'^giveFeedback$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing `giveFeedback()`. "
                        "ERC-8004 Reputation Registry requires feedback submission "
                        "with the constraint: submitter MUST NOT be the agent owner."
                    ),
                    recommendation=(
                        "```solidity\nfunction giveFeedback(\n"
                        "    uint256 agentId, int8 score, string calldata comment,\n"
                        "    string[] calldata tags\n"
                        ") external {\n"
                        "    require(ownerOf(agentId) != msg.sender, \"Owner cannot give feedback\");\n"
                        "    // store feedback ...\n"
                        "    emit NewFeedback(agentId, msg.sender, feedbackIndex);\n"
                        "}\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
            else:
                fn = next(f for f in contract.functions if f.name == 'giveFeedback')
                body = fn.body_text()
                if not re.search(r'owner|ownerOf', body):
                    findings.append(Finding(
                        rule_id=self.id,
                        title="ERC-8004: giveFeedback() Missing Owner Exclusion Check",
                        severity=Severity.HIGH,
                        lines=[fn.line],
                        description=(
                            "`giveFeedback()` exists but does not check that the submitter "
                            "is not the agent owner. ERC-8004 explicitly requires: "
                            "`require(ownerOf(agentId) != msg.sender)`"
                        ),
                        recommendation="Add: `require(ownerOf(agentId) != msg.sender, \"Owner cannot self-review\");`",
                        code_snippet=fn.raw,
                        mantle_specific=True, category=self.category
                    ))
        return findings


class E12_ReputationFunctions(RuleBase):
    id = "E-12"
    title = "ERC-8004: Incomplete Reputation Registry Functions"
    severity = Severity.MEDIUM
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        required = [
            ('revokeFeedback', 'revokeFeedback(uint256 agentId, uint64 feedbackIndex)'),
            ('appendResponse', 'appendResponse(uint256 agentId, ...)'),
            ('getSummary', 'getSummary(uint256 agentId, address[] clientAddresses, ...) returns (aggregated_scores)'),
            ('readFeedback', 'readFeedback(uint256 agentId, uint64 index)'),
            ('readAllFeedback', 'readAllFeedback(uint256 agentId)'),
            ('getClients', 'getClients(uint256 agentId) returns (address[])'),
        ]
        findings = []
        for contract in parsed.contracts:
            missing = [
                sig for name, sig in required
                if not _has_function(contract, r'^' + name + r'$')
            ]
            if missing:
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing Reputation Registry functions:\n"
                        + "\n".join(f"  • {s}" for s in missing)
                    ),
                    recommendation=(
                        "Implement all missing reputation functions to achieve full ERC-8004 compliance."
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E13_NewFeedbackEvent(RuleBase):
    id = "E-13"
    title = "ERC-8004: Missing NewFeedback Event"
    severity = Severity.MEDIUM
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_event(contract, r'^NewFeedback$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing the `NewFeedback` event. "
                        "Required: `event NewFeedback(uint256 indexed agentId, address indexed submitter, uint64 feedbackIndex)`"
                    ),
                    recommendation=(
                        "```solidity\nevent NewFeedback(\n"
                        "    uint256 indexed agentId,\n"
                        "    address indexed submitter,\n"
                        "    uint64 feedbackIndex\n"
                        ");\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


# ── Validation Registry ────────────────────────────────────────────────────

class E14_ValidationFunctions(RuleBase):
    id = "E-14"
    title = "ERC-8004: Missing Validation Registry Functions"
    severity = Severity.HIGH
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        required = [
            ('validationRequest', 'validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)'),
            ('validationResponse', 'validationResponse(bytes32 requestHash, uint8 response, ...)'),
            ('getValidationStatus', 'getValidationStatus(bytes32 requestHash) returns (outcome)'),
            ('getAgentValidations', 'getAgentValidations(uint256 agentId) returns (all requests)'),
        ]
        findings = []
        for contract in parsed.contracts:
            missing = [
                sig for name, sig in required
                if not _has_function(contract, r'^' + name + r'$')
            ]
            if missing:
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing Validation Registry functions:\n"
                        + "\n".join(f"  • {s}" for s in missing)
                    ),
                    recommendation=(
                        "The Validation Registry is the cryptographic proof-of-work layer. "
                        "Implement all missing functions. Supported mechanisms: stake-slashing, "
                        "ZK proofs, TEE oracles."
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


class E15_ValidationResponseEvent(RuleBase):
    id = "E-15"
    title = "ERC-8004: Missing ValidationResponse Event"
    severity = Severity.MEDIUM
    category = "compliance"
    mantle_specific = True

    def check(self, parsed: ParsedFile) -> List[Finding]:
        findings = []
        for contract in parsed.contracts:
            if not _has_event(contract, r'^ValidationResponse$'):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    lines=[contract.line],
                    description=(
                        f"Contract `{contract.name}` is missing the `ValidationResponse` event. "
                        "Required: `event ValidationResponse(bytes32 indexed requestHash, uint8 response, address indexed validator)`"
                    ),
                    recommendation=(
                        "```solidity\nevent ValidationResponse(\n"
                        "    bytes32 indexed requestHash,\n"
                        "    uint8 response,\n"
                        "    address indexed validator\n"
                        ");\n```"
                    ),
                    code_snippet=f"contract {contract.name}",
                    mantle_specific=True, category=self.category
                ))
        return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
ALL_ERC8004_RULES: List[RuleBase] = [
    E01_RegisterFunction(),
    E02_SetAgentURI(),
    E03_GetMetadata(),
    E04_SetMetadata(),
    E05_SetAgentWallet(),
    E06_AgentWalletGetUnset(),
    E07_RegisteredEvent(),
    E08_MetadataSetEvent(),
    E09_ERC721Inheritance(),
    E10_SupportsInterface(),
    E11_GiveFeedback(),
    E12_ReputationFunctions(),
    E13_NewFeedbackEvent(),
    E14_ValidationFunctions(),
    E15_ValidationResponseEvent(),
]
