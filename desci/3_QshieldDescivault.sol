// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract QshieldDescivault {
    using ECDSA for bytes32;

    // ==================== CONFIG ====================
    address public immutable ADMIN;
    address public immutable DATA_SIGNER;
    mapping(address => bool) public isModerator;

    // ==================== DATA STRUCTS ====================
    struct SubmissionData {
        bytes32 submissionHash;     // keccak256 of encrypted blob + metadata
        string cid;                 // IPFS/Arweave link
        string title;
        string[] tags;
        string doi;
        uint256 projectId;
        bool isPublic;
    }

    struct DataEntry {
        bytes32 submissionHash;
        string cid;
        string title;
        string[] tags;
        string doi;
        uint256 projectId;
        address researcher;
        uint256 submissionTimestamp;
        bool isPublic;
    }

    DataEntry[] public entries;

    mapping(uint256 => uint256[]) public projectToEntryIds;
    mapping(bytes32 => uint256) public submissionHashToEntryId;

    // ==================== EVENTS ====================
    event DataSubmitted(
        uint256 indexed entryId,
        bytes32 indexed submissionHash,
        uint256 indexed projectId,
        address researcher,
        string cid,
        string title,
        bool isPublic
    );
    event EntryRevoked(uint256 indexed entryId, bytes32 submissionHash);
    event ModeratorAdded(address moderator);
    event ModeratorRemoved(address moderator);

    // ==================== MODIFIERS ====================
    modifier onlyAdmin() {
        require(msg.sender == ADMIN, "Not admin");
        _;
    }

    modifier onlyModerator() {
        require(msg.sender == ADMIN || isModerator[msg.sender], "Not moderator");
        _;
    }

    constructor(address dataSigner) {
        require(dataSigner != address(0), "Signer zero");
        ADMIN = msg.sender;
        DATA_SIGNER = dataSigner;
    }

    // ==================== CORE SUBMISSION ====================
    // Split into two functions to completely eliminate stack-too-deep
    // 1. Submit the signed payload (no storage writes yet)
    // 2. Finalize the submission (called internally)
    function submitData(
        SubmissionData calldata data,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(bytes(data.cid).length > 0, "CID required");
        require(bytes(data.title).length > 0, "Title required");
        require(submissionHashToEntryId[data.submissionHash] == 0, "Duplicate submission");

        // Compute and verify signature — all variables fit comfortably in stack
        bytes32 messageHash = keccak256(
            abi.encode(
                msg.sender,
                data.submissionHash,
                data.projectId,
                nonce,
                block.chainid
            )
        );
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        require(ECDSA.recover(prefixedHash, v, r, s) == DATA_SIGNER, "Invalid signature");

        // Now perform storage writes in separate internal function
        _finalizeSubmission(data);
    }

    function _finalizeSubmission(SubmissionData calldata data) internal {
        uint256 entryId = entries.length;

        entries.push(DataEntry({
            submissionHash: data.submissionHash,
            cid: data.cid,
            title: data.title,
            tags: data.tags,
            doi: data.doi,
            projectId: data.projectId,
            researcher: msg.sender,
            submissionTimestamp: block.timestamp,
            isPublic: data.isPublic
        }));

        submissionHashToEntryId[data.submissionHash] = entryId;
        projectToEntryIds[data.projectId].push(entryId);

        emit DataSubmitted(
            entryId,
            data.submissionHash,
            data.projectId,
            msg.sender,
            data.cid,
            data.title,
            data.isPublic
        );
    }

    // ==================== MODERATOR ACTIONS ====================
    function revokeEntry(uint256 entryId) external onlyModerator {
        require(entryId < entries.length, "Invalid entry");
        DataEntry storage entry = entries[entryId];
        require(submissionHashToEntryId[entry.submissionHash] != 0, "Already revoked");

        bytes32 hash = entry.submissionHash;
        delete submissionHashToEntryId[hash];

        emit EntryRevoked(entryId, hash);
    }

    // ==================== ADMIN ====================
    function addModerator(address mod) external onlyAdmin {
        isModerator[mod] = true;
        emit ModeratorAdded(mod);
    }

    function removeModerator(address mod) external onlyAdmin {
        isModerator[mod] = false;
        emit ModeratorRemoved(mod);
    }

    // ==================== VIEW FUNCTIONS ====================
    function getEntry(uint256 entryId) external view returns (DataEntry memory) {
        require(entryId < entries.length, "Invalid entry");
        return entries[entryId];
    }

    function getEntriesByProject(uint256 projectId) external view returns (uint256[] memory) {
        return projectToEntryIds[projectId];
    }

    function getTotalEntries() external view returns (uint256) {
        return entries.length;
    }

    function getEntriesRange(uint256 start, uint256 count) external view returns (DataEntry[] memory) {
        require(start < entries.length, "Start out of bounds");
        uint256 end = start + count > entries.length ? entries.length : start + count;
        DataEntry[] memory result = new DataEntry[](end - start);
        for (uint256 i = start; i < end; i++) {
            result[i - start] = entries[i];
        }
        return result;
    }
}
