// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract QshieldLeaderboard2 {
    using ECDSA for bytes32;

    // ==================== CONFIG ====================
    address public immutable ADMIN;
    address public immutable GAME_SIGNER;
    uint256 public immutable MAX_ENTRIES = 50;
    mapping(address => bool) public isModerator;

    // ==================== DATA  ====================
    mapping(bytes32 => uint256) public scores;           // idHash => score for this specific submission
    mapping(address => uint256) public scores2;          // player address => personal best score (across all their submissions)
    mapping(bytes32 => string) public identifierOf;
    mapping(bytes32 => bool) public disqualified;
    mapping(bytes32 => uint256) private heapIndex;       // idHash => position in leaderboard (0 = not present)

    struct Entry {
        bytes32 idHash;
        uint256 score;
    }
    Entry[] private leaderboard; // index 0 unused → min-heap of the top MAX_ENTRIES

    // ==================== EVENTS & MODIFIERS ====================
    event ScoreSubmitted(bytes32 indexed idHash, string identifier, uint256 score, address player);
    event ScoreDisqualified(bytes32 indexed idHash, string identifier);
    event ModeratorAdded(address moderator);
    event ModeratorRemoved(address moderator);

    modifier onlyAdmin() { require(msg.sender == ADMIN, "Not admin"); _; }
    modifier onlyModerator() { require(msg.sender == ADMIN || isModerator[msg.sender], "Not moderator"); _; }

    constructor(address gameSigner) {
        require(gameSigner != address(0), "Signer zero");
        ADMIN = msg.sender;
        GAME_SIGNER = gameSigner;
        leaderboard.push(Entry(bytes32(0), 0)); // dummy index 0
    }

    function submitScore(
        string calldata identifier,
        uint256 score,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(score > 0, "Score > 0");

        // === Signature verification ===
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, identifier, score, nonce, block.chainid));
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        require(ECDSA.recover(prefixedHash, v, r, s) == GAME_SIGNER, "Invalid sig");

        bytes32 idHash = keccak256(abi.encodePacked(identifier));
        require(!disqualified[idHash], "Disqualified");

        // Store this specific submission
        scores[idHash] = score;
        identifierOf[idHash] = identifier;

        // Update player's personal best if this submission beats it
        if (score > scores2[msg.sender]) {
            scores2[msg.sender] = score;
        }

        // Leaderboard handling
        uint256 pos = heapIndex[idHash];

        if (pos != 0) {
            // Already in leaderboard → update score and rebalance
            leaderboard[pos].score = score;
            _bubbleUp(pos);
            _bubbleDown(1);
        } else if (leaderboard.length < MAX_ENTRIES + 1) {
            // Still room → insert new entry
            _insertNew(idHash, score);
        } else if (score > leaderboard[1].score) {
            // Better than current worst → replace worst
            _replaceWorst(idHash, score);
        }

        emit ScoreSubmitted(idHash, identifier, score, msg.sender);
    }

    // ====================== INTERNAL HEAP  ===========================

    function _insertNew(bytes32 idHash, uint256 score) private {
        leaderboard.push(Entry(idHash, score));
        uint256 idx = leaderboard.length - 1;
        heapIndex[idHash] = idx;
        _bubbleUp(idx);
    }

    function _replaceWorst(bytes32 idHash, uint256 score) private {
        // Remove old worst
        bytes32 oldHash = leaderboard[1].idHash;
        heapIndex[oldHash] = 0;

        // Overwrite root
        leaderboard[1] = Entry(idHash, score);
        heapIndex[idHash] = 1;

        // Restore min-heap property
        _bubbleDown(1);
    }

    function _bubbleUp(uint256 i) private {
        Entry memory cand = leaderboard[i];
        while (i > 1) {
            uint256 parent = i / 2;
            if (leaderboard[parent].score <= cand.score) break;

            leaderboard[i] = leaderboard[parent];
            heapIndex[leaderboard[i].idHash] = i;

            i = parent;
        }
        leaderboard[i] = cand;
        heapIndex[cand.idHash] = i;
    }

    function _bubbleDown(uint256 i) private {
        Entry memory cand = leaderboard[i];
        uint256 size = leaderboard.length;

        while (true) {
            uint256 left = i * 2;
            uint256 right = left + 1;
            uint256 smallest = i;

            if (left < size && leaderboard[left].score < leaderboard[smallest].score)
                smallest = left;
            if (right < size && leaderboard[right].score < leaderboard[smallest].score)
                smallest = right;

            if (smallest == i) break;

            leaderboard[i] = leaderboard[smallest];
            heapIndex[leaderboard[i].idHash] = i;
            i = smallest;
        }
        leaderboard[i] = cand;
        heapIndex[cand.idHash] = i;
    }

    // ====================== DISQUALIFY ========================
    function disqualify(string calldata identifier) external onlyModerator {
        bytes32 idHash = keccak256(abi.encodePacked(identifier));
        uint256 idx = heapIndex[idHash];
        if (idx == 0) return;

        uint256 last = leaderboard.length - 1;
        bytes32 lastHash = leaderboard[last].idHash;

        if (idx != last) {
            // Move last to removed position
            leaderboard[idx] = leaderboard[last];
            heapIndex[lastHash] = idx;

            // Rebalance
            _bubbleUp(idx);
            _bubbleDown(idx);
        }

        leaderboard.pop();
        heapIndex[idHash] = 0;
        delete scores[idHash];
        delete identifierOf[idHash];

        emit ScoreDisqualified(idHash, identifier);
    }

    // ====================== ADMIN ======================
    function addModerator(address mod) external onlyAdmin {
        isModerator[mod] = true;
        emit ModeratorAdded(mod);
    }

    function removeModerator(address mod) external onlyAdmin {
        isModerator[mod] = false;
        emit ModeratorRemoved(mod);
    }

    // ====================== VIEW  =========================
    function getTop() external view returns (string[] memory identifiers, uint256[] memory topScores) {
        uint256 len = leaderboard.length - 1;
        if (len > MAX_ENTRIES) len = MAX_ENTRIES;

        identifiers = new string[](len);
        topScores = new uint256[](len);

        // Temporary copy to sort in memory (descending)
        Entry[] memory copy = new Entry[](len);
        for (uint256 i = 0; i < len; i++) {
            copy[i] = leaderboard[i + 1];
        }

        // Simple insertion sort (gas-efficient for small N <= 50)
        for (uint256 i = 1; i < len; i++) {
            Entry memory key = copy[i];
            uint256 j = i;
            while (j > 0 && copy[j-1].score < key.score) {
                copy[j] = copy[j-1];
                j--;
            }
            copy[j] = key;
        }

        for (uint256 i = 0; i < len; i++) {
            bytes32 h = copy[i].idHash;
            identifiers[i] = bytes(identifierOf[h]).length > 0 ? identifierOf[h] : _bytes32ToHex(h);
            topScores[i] = copy[i].score;
        }
    }

    function getScore() external view returns (uint256) {
        return scores2[msg.sender];
    }

    function getSize() external pure returns (uint256){
        return MAX_ENTRIES;
    }

    function _bytes32ToHex(bytes32 b) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i*2] = alphabet[uint8(b[i] >> 4)];
            str[i*2+1] = alphabet[uint8(b[i] & 0x0f)];
        }
        return string(str);
    }
}
