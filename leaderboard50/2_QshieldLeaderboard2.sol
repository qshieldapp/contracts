// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract QshieldLeaderboard2 {
    using ECDSA for bytes32;
    // ==================== CONFIG ====================
    address public immutable ADMIN;
    address public immutable GAME_SIGNER; // the backend signing key

    mapping(address => bool) public isModerator;

    uint256 public constant MAX_ENTRIES = 50;

    // ==================== DATA ====================
    mapping(bytes32 => uint256) public scores;           // idHash => score
    mapping(address => uint256) public scores2;          // wallet => score
    mapping(bytes32 => string) public identifierOf;      // only stored for top players
    mapping(bytes32 => bool) public disqualified;

    struct Entry {
        bytes32 idHash;
        uint256 score;
    }
    Entry[] private leaderboard; // max-heap (index 0 is unused)

    // ==================== EVENTS ====================
    event ScoreSubmitted(bytes32 indexed idHash, string identifier, uint256 score, address player);
    event ScoreDisqualified(bytes32 indexed idHash, string identifier);
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

    // ==================== CONSTRUCTOR ====================
    constructor(address gameSigner) {
        require(gameSigner != address(0), "Signer zero");
        ADMIN = msg.sender;
        GAME_SIGNER = gameSigner;
        leaderboard.push(Entry(bytes32(0), 0)); // dummy at index 0
    }

    // ==================== USER: SIGNED SUBMISSION ====================
    function submitScore(
        string calldata identifier,
        uint256 score,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(score > 0, "Score > 0");

        // === Signature verification (the real security) ===
        bytes32 messageHash = keccak256(abi.encodePacked(
            msg.sender,
            identifier,
            score,
            nonce,
            block.chainid
        )); 
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address recovered = ECDSA.recover(prefixedHash, v, r, s);
        require(recovered == GAME_SIGNER, "Invalid signature");

        bytes32 idHash = keccak256(abi.encodePacked(identifier));
        require(!disqualified[idHash], "Disqualified");

        uint256 oldScore = scores[idHash];
        if (score <= oldScore) return; // no improvement

        scores[idHash] = score;
        scores2[msg.sender] = score;

        // Store original string only when they enter top 30
        if (oldScore == 0 && score > leaderboard[leaderboard.length - 1].score) {
            identifierOf[idHash] = identifier;
        }

        if (_existsInLeaderboard(idHash)) {
            _updateInHeap(idHash, score);
        } else if (score > leaderboard[leaderboard.length - 1].score) {
            _insertOrReplace(idHash, score);
            if (oldScore == 0) identifierOf[idHash] = identifier;
        }

        emit ScoreSubmitted(idHash, identifier, score, msg.sender);
    }

    // ==================== MODERATOR: DISQUALIFY ====================
    function disqualify(string calldata identifier) external onlyModerator {
        bytes32 idHash = keccak256(abi.encodePacked(identifier));
        if (scores[idHash] == 0) return;

        disqualified[idHash] = true;
        delete scores[idHash];
        delete identifierOf[idHash];

        if (_existsInLeaderboard(idHash)) {
            _removeFromHeap(idHash);
        }

        emit ScoreDisqualified(idHash, identifier);
    }

    // ==================== ADMIN FUNCTIONS ====================
    function addModerator(address mod) external onlyAdmin {
        isModerator[mod] = true;
        emit ModeratorAdded(mod);
    }

    function removeModerator(address mod) external onlyAdmin {
        isModerator[mod] = false;
        emit ModeratorRemoved(mod);
    }

    // ==================== VIEW: TOP 30 ====================
    function getTop() external view returns (string[] memory identifiers, uint256[] memory topScores) {
        uint256 len = leaderboard.length > 1 ? leaderboard.length - 1 : 0;
        identifiers = new string[](len);
        topScores = new uint256[](len);

        for (uint256 i = 0; i < len; i++) {
            bytes32 idHash = leaderboard[i + 1].idHash;
            string memory id = identifierOf[idHash];
            identifiers[i] = bytes(id).length > 0 ? id : _bytes32ToHex(idHash);
            topScores[i] = leaderboard[i + 1].score;
        }
    }

    // ==================== VIEW: Your Score ================
    function getScore() external view returns (uint256){
        uint256 scr = scores2[msg.sender];
        return scr;
    }

    // ==================== INTERNAL HEAP LOGIC ====================
    function _existsInLeaderboard(bytes32 idHash) internal view returns (bool) {
        for (uint256 i = 1; i < leaderboard.length; i++) {
            if (leaderboard[i].idHash == idHash) return true;
        }
        return false;
    }

    function _updateInHeap(bytes32 idHash, uint256 newScore) internal {
        for (uint256 i = 1; i < leaderboard.length; i++) {
            if (leaderboard[i].idHash == idHash) {
                leaderboard[i].score = newScore;
                _bubbleUp(i);
                _bubbleDown(i);
                break;
            }
        }
    }

    function _insertOrReplace(bytes32 idHash, uint256 score) internal {
        if (leaderboard.length <= MAX_ENTRIES) {
            leaderboard.push(Entry(idHash, score));
            _bubbleUp(leaderboard.length - 1);
        } else {
            leaderboard[leaderboard.length - 1] = Entry(idHash, score);
            _bubbleUp(leaderboard.length - 1);
        }
    }

    function _removeFromHeap(bytes32 idHash) internal {
        uint256 len = leaderboard.length;
        uint256 idx = type(uint256).max;

        for (uint256 i = 1; i < len; i++) {
            if (leaderboard[i].idHash == idHash) {
                idx = i;
                break;
            }
        }
        if (idx == type(uint256).max) return;

        leaderboard[idx] = leaderboard[len - 1];
        leaderboard.pop();

        if (idx < leaderboard.length) {
            _bubbleUp(idx);
            _bubbleDown(idx);
        }
    }

    function _bubbleUp(uint256 i) internal {
        Entry memory temp = leaderboard[i];
        while (i > 1) {
            uint256 parent = i / 2;
            if (leaderboard[parent].score >= temp.score) break;
            leaderboard[i] = leaderboard[parent];
            i = parent;
        }
        leaderboard[i] = temp;
    }

    function _bubbleDown(uint256 i) internal {
        Entry memory temp = leaderboard[i];
        uint256 len = leaderboard.length;

        while (true) {
            uint256 left = i * 2;
            uint256 right = left + 1;
            uint256 largest = i;

            if (left < len && leaderboard[left].score > leaderboard[largest].score)
                largest = left;
            if (right < len && leaderboard[right].score > leaderboard[largest].score)
                largest = right;

            if (largest == i) break;
            leaderboard[i] = leaderboard[largest];
            i = largest;
        }
        leaderboard[i] = temp;
    }

    function _bytes32ToHex(bytes32 b) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i*2]   = alphabet[uint8(b[i] >> 4)];
            str[i*2+1] = alphabet[uint8(b[i] & 0x0f)];
        }
        return string(str);
    }
}
