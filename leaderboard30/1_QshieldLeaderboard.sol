// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract QshieldLeaderboard {
    using ECDSA for bytes32;

    // ==================== CONFIG ====================
    address public immutable ADMIN;
    address public immutable GAME_SIGNER;
    uint256 public immutable MAX_ENTRIES = 30;
    mapping(address => bool) public isModerator;

    // ==================== DATA  ====================
    mapping(bytes32 => uint256) public scores;           
    mapping(address => uint256) public scores2;          
    mapping(bytes32 => string) public identifierOf;
    mapping(bytes32 => bool) public disqualified;

    struct Entry {
        bytes32 idHash;
        uint256 score;
    }
    Entry[] private leaderboard; // Unsorted array of top entries (length <= MAX_ENTRIES)

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

        // Signature verification
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, identifier, score, nonce, block.chainid));
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        require(ECDSA.recover(prefixedHash, v, r, s) == GAME_SIGNER, "Invalid sig");

        bytes32 idHash = keccak256(abi.encodePacked(identifier));
        require(!disqualified[idHash], "Disqualified");

        scores[idHash] = score;
        identifierOf[idHash] = identifier;

        if (score > scores2[msg.sender]) {
            scores2[msg.sender] = score;
        }

        // Check if this idHash is already in the leaderboard
        bool alreadyIn = false;
        uint256 existingIndex;
        for (uint256 i = 0; i < leaderboard.length; i++) {
            if (leaderboard[i].idHash == idHash) {
                alreadyIn = true;
                existingIndex = i;
                break;
            }
        }

        if (alreadyIn) {
            // Update existing entry's score
            leaderboard[existingIndex].score = score;
        } else {
            // New potential entry
            if (leaderboard.length < MAX_ENTRIES) {
                // Room left → just add it
                leaderboard.push(Entry(idHash, score));
            } else {
                // Full → find the current lowest score
                uint256 lowestScore = type(uint256).max;
                uint256 lowestIndex = 0;
                for (uint256 i = 0; i < leaderboard.length; i++) {
                    if (leaderboard[i].score < lowestScore) {
                        lowestScore = leaderboard[i].score;
                        lowestIndex = i;
                    }
                }

                if (score > lowestScore) {
                    // Replace the lowest with the new one
                    leaderboard[lowestIndex] = Entry(idHash, score);
                }
                // else: too low, ignore
            }
        }

        emit ScoreSubmitted(idHash, identifier, score, msg.sender);
    }

    // ====================== DISQUALIFY ========================
    function disqualify(string calldata identifier) external onlyModerator {
        bytes32 idHash = keccak256(abi.encodePacked(identifier));
        disqualified[idHash] = true;

        // Remove from leaderboard if present
        for (uint256 i = 0; i < leaderboard.length; i++) {
            if (leaderboard[i].idHash == idHash) {
                // Move last element to this position and pop
                leaderboard[i] = leaderboard[leaderboard.length - 1];
                leaderboard.pop();
                break;
            }
        }

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

    // ====================== VIEW =========================
    function getTop() external view returns (string[] memory identifiers, uint256[] memory topScores) {
        uint256 len = leaderboard.length;
        identifiers = new string[](len);
        topScores = new uint256[](len);

        // Create a copy for sorting
        Entry[] memory copy = new Entry[](len);
        for (uint256 i = 0; i < len; i++) {
            copy[i] = leaderboard[i];
        }

        // Insertion sort descending (highest scores first)
        for (uint256 i = 1; i < len; i++) {
            Entry memory key = copy[i];
            uint256 j = i;
            while (j > 0 && copy[j - 1].score < key.score) {
                copy[j] = copy[j - 1];
                j--;
            }
            copy[j] = key;
        }

        // Build return arrays
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
            str[i * 2] = alphabet[uint8(b[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(b[i] & 0x0f)];
        }
        return string(str);
    }
}
