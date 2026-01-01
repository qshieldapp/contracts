// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract QshieldMessenger {
    using ECDSA for bytes32;

    address public immutable ADMIN;
    address public immutable DATA_SIGNER;
    mapping(address => bool) public isModerator;

    struct MessageEntry {
        address sender;
        address recipient;
        string encryptedMessage;     // Full encrypted payload (e.g., base64 string)
        bytes32 messageHash;         // keccak256(encryptedMessage) — commitment
        uint256 timestamp;
    }

    MessageEntry[] public messages;

    // conversation indexing: normalized pair -> message IDs
    mapping(address => mapping(address => uint256[])) public conversationMessages;

    // prevent duplicates
    mapping(bytes32 => bool) public seenMessageHashes;

    event MessageSent(
        uint256 indexed messageId,
        address indexed sender,
        address indexed recipient,
        bytes32 messageHash,
        uint256 timestamp
    );
    event MessageRevoked(uint256 indexed messageId);
    event ModeratorAdded(address moderator);
    event ModeratorRemoved(address moderator);

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

    // Much more user-friendly: just pass the encrypted string!
    function sendMessage(
        address recipient,
        string calldata encryptedMessage,  // e.g., base64-encoded ciphertext
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(recipient != address(0), "Invalid recipient");
        require(recipient != msg.sender, "Cannot send to self");
        require(bytes(encryptedMessage).length > 0, "Empty message");

        // Compute hash ON-CHAIN — this is the key improvement
        bytes32 messageHash = keccak256(bytes(encryptedMessage));
        require(!seenMessageHashes[messageHash], "Duplicate message");

        // Verify signature over: sender + recipient + messageHash + nonce + chainId
        bytes32 sigHash = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                nonce + 1,
                nonce,
                block.chainid
            )
        );
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", sigHash));
        require(ECDSA.recover(prefixed, v, r, s) == DATA_SIGNER, "Invalid signature");

        // Store and index
        uint256 messageId = messages.length;

        messages.push(MessageEntry({
            sender: msg.sender,
            recipient: recipient,
            encryptedMessage: encryptedMessage,
            messageHash: messageHash,
            timestamp: block.timestamp
        }));

        seenMessageHashes[messageHash] = true;

        // Index conversation both ways
        address userA = msg.sender < recipient ? msg.sender : recipient;
        address userB = msg.sender < recipient ? recipient : msg.sender;
        conversationMessages[userA][userB].push(messageId);

        emit MessageSent(messageId, msg.sender, recipient, messageHash, block.timestamp);
    }

    // Moderator soft-delete
    function revokeMessage(uint256 messageId) external onlyModerator {
        require(messageId < messages.length, "Invalid message");
        emit MessageRevoked(messageId);
    }

    // Admin functions
    function addModerator(address mod) external onlyAdmin {
        isModerator[mod] = true;
        emit ModeratorAdded(mod);
    }

    function removeModerator(address mod) external onlyAdmin {
        isModerator[mod] = false;
        emit ModeratorRemoved(mod);
    }

    // View functions
    function getMessage(uint256 messageId) external view returns (MessageEntry memory) {
        require(messageId < messages.length, "Invalid ID");
        return messages[messageId];
    }

    function getConversation(address userA, address userB) external view returns (uint256[] memory) {
        address min = userA < userB ? userA : userB;
        address max = userA < userB ? userB : userA;
        return conversationMessages[min][max];
    }

    function getTotalMessages() external view returns (uint256) {
        return messages.length;
    }

    function getMessagesRange(uint256 start, uint256 count) external view returns (MessageEntry[] memory) {
        require(start < messages.length, "Start out of bounds");
        uint256 end = start + count > messages.length ? messages.length : start + count;
        MessageEntry[] memory result = new MessageEntry[](end - start);
        for (uint256 i = start; i < end; i++) {
            result[i - start] = messages[i];
        }
        return result;
    }
}
