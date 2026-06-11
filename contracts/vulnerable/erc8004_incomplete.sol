// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * IncompleteAgentRegistry — intentionally incomplete ERC-8004 implementation for testing.
 * Missing: Reputation registry, Validation registry, proper EIP-712 for wallet changes,
 *          ERC-165 supportsInterface, several required events.
 */

interface IERC721 {
    function balanceOf(address owner) external view returns (uint256);
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
}

contract IncompleteAgentRegistry is IERC721 {
    uint256 private _tokenIdCounter;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;

    // Identity data — partial implementation
    mapping(uint256 => string) private _agentURIs;
    mapping(uint256 => mapping(string => bytes)) private _metadata;
    mapping(uint256 => address) private _agentWallets;

    // Missing: Reputation registry mappings
    // Missing: Validation registry mappings

    // Missing: proper event signatures
    event AgentRegistered(uint256 tokenId, address owner);  // Missing agentURI in event
    // Missing: MetadataSet event
    // Missing: NewFeedback event
    // Missing: ValidationResponse event

    // register — missing MetadataEntry[] parameter
    function register(string calldata agentURI) external returns (uint256) {
        uint256 tokenId = ++_tokenIdCounter;
        _owners[tokenId] = msg.sender;
        _balances[msg.sender]++;
        _agentURIs[tokenId] = agentURI;

        emit AgentRegistered(tokenId, msg.sender);
        return tokenId;
    }

    function setAgentURI(uint256 agentId, string calldata newURI) external {
        require(_owners[agentId] == msg.sender, "Not owner");
        _agentURIs[agentId] = newURI;
        // Missing: emit MetadataSet
    }

    function getMetadata(uint256 agentId, string calldata key) external view returns (bytes memory) {
        return _metadata[agentId][key];
    }

    function setMetadata(uint256 agentId, string calldata key, bytes calldata value) external {
        require(_owners[agentId] == msg.sender, "Not owner");
        _metadata[agentId][key] = value;
        // Missing: emit MetadataSet
    }

    // Missing EIP-712 signature verification for wallet changes
    function setAgentWallet(uint256 agentId, address newWallet) external {
        // BUG: No EIP-712 signature check — should require signed message with deadline
        require(_owners[agentId] == msg.sender, "Not owner");
        _agentWallets[agentId] = newWallet;
    }

    function getAgentWallet(uint256 agentId) external view returns (address) {
        return _agentWallets[agentId];
    }

    function unsetAgentWallet(uint256 agentId) external {
        require(_owners[agentId] == msg.sender, "Not owner");
        delete _agentWallets[agentId];
    }

    // ERC-721 implementations
    function balanceOf(address owner) external view returns (uint256) {
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        return _owners[tokenId];
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(_owners[tokenId] == from, "Not owner");
        require(
            msg.sender == from || msg.sender == _tokenApprovals[tokenId],
            "Not approved"
        );
        _owners[tokenId] = to;
        _balances[from]--;
        _balances[to]++;
        delete _tokenApprovals[tokenId];
    }

    function approve(address to, uint256 tokenId) external {
        require(_owners[tokenId] == msg.sender, "Not owner");
        _tokenApprovals[tokenId] = to;
    }

    // Missing: supportsInterface (ERC-165)
    // Missing: Reputation Registry functions (giveFeedback, revokeFeedback, etc.)
    // Missing: Validation Registry functions (validationRequest, validationResponse, etc.)
}
