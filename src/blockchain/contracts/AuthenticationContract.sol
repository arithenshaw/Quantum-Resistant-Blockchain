// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title QuantumResistantAuthentication
 * @dev Smart contract for quantum-resistant blockchain authentication
 */
contract QuantumResistantAuthentication {
    // Events
    event UserRegistered(address indexed userAddress, string userId, uint256 timestamp);
    event UserAuthenticated(string indexed userId, uint256 timestamp);
    event KeyRotated(string indexed userId, bytes32 oldKeyHash, bytes32 newKeyHash, uint256 timestamp);
    event KeyRevoked(string indexed userId, bytes32 keyHash, uint256 timestamp, string reason);
    
    // Structs
    struct PublicKeys {
        string encryptionKey;    // JSON string containing hybrid encryption key (ECC + Kyber)
        string signatureKey;     // JSON string containing hybrid signature key (ECDSA + Dilithium)
        bytes32 encryptionKeyHash;
        bytes32 signatureKeyHash;
        uint256 registrationTime;
        bool active;
    }
    
    struct User {
        string userId;
        address ethAddress;
        PublicKeys currentKeys;
        mapping(bytes32 => PublicKeyHistory) keyHistory;
        uint256 lastAuthenticated;
        bool exists;
    }
    
    struct PublicKeyHistory {
        string keyData;
        uint256 activationTime;
        uint256 revocationTime;
        string revocationReason;
        bool wasRevoked;
    }
    
    // State variables
    mapping(string => User) private users;
    mapping(address => string) private addressToUserId;
    
    // Administrators who can perform emergency revocations
    mapping(address => bool) private administrators;
    address private contractOwner;
    
    // Modifiers
    modifier onlyAdmin() {
        require(administrators[msg.sender] || msg.sender == contractOwner, "Not authorized");
        _;
    }
    
    modifier onlyExistingUser(string memory userId) {
        require(users[userId].exists, "User does not exist");
        _;
    }
    
    modifier onlyUserOrAdmin(string memory userId) {
        require(
            keccak256(abi.encodePacked(addressToUserId[msg.sender])) == keccak256(abi.encodePacked(userId)) || 
            administrators[msg.sender] || 
            msg.sender == contractOwner, 
            "Not authorized"
        );
        _;
    }
    
    // Constructor
    constructor() {
        contractOwner = msg.sender;
        administrators[msg.sender] = true;
    }
    
    /**
     * @dev Add an administrator
     * @param admin Address of the new administrator
     */
    function addAdministrator(address admin) external onlyAdmin {
        administrators[admin] = true;
    }
    
    /**
     * @dev Remove an administrator
     * @param admin Address of the administrator to remove
     */
    function removeAdministrator(address admin) external onlyAdmin {
        require(admin != contractOwner, "Cannot remove contract owner");
        administrators[admin] = false;
    }
    
    /**
     * @dev Register a new user with quantum-resistant keys
     * @param userId Unique identifier for the user
     * @param encryptionKey Hybrid encryption public key (ECC + Kyber)
     * @param signatureKey Hybrid signature public key (ECDSA + Dilithium)
     * @param signature Signature proving ownership of the keys
     * @return success Whether the registration was successful
     */
    function registerUser(
        string memory userId, 
        string memory encryptionKey, 
        string memory signatureKey,
        bytes memory signature
    ) external returns (bool success) {
        // Check that the user ID is not already taken
        require(!users[userId].exists, "User ID already registered");
        require(bytes(addressToUserId[msg.sender]).length == 0, "Address already registered");
        
        // Verify the signature (this would be implemented off-chain in a real system)
        // For simplicity, we're skipping the signature verification in this example
        
        // Create encryption key hash
        bytes32 encKeyHash = keccak256(abi.encodePacked(encryptionKey));
        
        // Create signature key hash
        bytes32 sigKeyHash = keccak256(abi.encodePacked(signatureKey));
        
        // Create PublicKeys struct
        PublicKeys memory keys = PublicKeys({
            encryptionKey: encryptionKey,
            signatureKey: signatureKey,
            encryptionKeyHash: encKeyHash,
            signatureKeyHash: sigKeyHash,
            registrationTime: block.timestamp,
            active: true
        });
        
        // Store user data
        users[userId].userId = userId;
        users[userId].ethAddress = msg.sender;
        users[userId].currentKeys = keys;
        users[userId].lastAuthenticated = block.timestamp;
        users[userId].exists = true;
        
        // Map Ethereum address to user ID
        addressToUserId[msg.sender] = userId;
        
        // Add to key history
        users[userId].keyHistory[encKeyHash] = PublicKeyHistory({
            keyData: encryptionKey,
            activationTime: block.timestamp,
            revocationTime: 0,
            revocationReason: "",
            wasRevoked: false
        });
        
        users[userId].keyHistory[sigKeyHash] = PublicKeyHistory({
            keyData: signatureKey,
            activationTime: block.timestamp,
            revocationTime: 0,
            revocationReason: "",
            wasRevoked: false
        });
        
        // Emit registration event
        emit UserRegistered(msg.sender, userId, block.timestamp);
        
        return true;
    }
    
    /**
     * @dev Record a successful authentication
     * @param userId ID of the authenticated user
     * @param authSignature Signature of the authentication challenge
     * @return success Whether the authentication was recorded
     */
    function recordAuthentication(
        string memory userId, 
        bytes memory authSignature
    ) external onlyAdmin onlyExistingUser(userId) returns (bool success) {
        // For a real implementation, verify the signature here or before calling
        // This would typically be done off-chain, and we'd just record the event
        
        // Update last authentication time
        users[userId].lastAuthenticated = block.timestamp;
        
        // Emit authentication event
        emit UserAuthenticated(userId, block.timestamp);
        
        return true;
    }
    
    /**
     * @dev Rotate keys for a user (update to new quantum-resistant keys)
     * @param userId ID of the user
     * @param newEncryptionKey New hybrid encryption public key
     * @param newSignatureKey New hybrid signature public key
     * @param signature Signature proving ownership of the old keys
     * @return success Whether the key rotation was successful
     */
    function rotateKeys(
        string memory userId, 
        string memory newEncryptionKey, 
        string memory newSignatureKey,
        bytes memory signature
    ) external onlyUserOrAdmin(userId) onlyExistingUser(userId) returns (bool success) {
        // Get user data
        User storage user = users[userId];
        
        // Verify the signature (this would be implemented off-chain in a real system)
        // For simplicity, we're skipping the signature verification in this example
        
        // Hash the old keys for reference
        bytes32 oldEncKeyHash = user.currentKeys.encryptionKeyHash;
        bytes32 oldSigKeyHash = user.currentKeys.signatureKeyHash;
        
        // Create new encryption key hash
        bytes32 newEncKeyHash = keccak256(abi.encodePacked(newEncryptionKey));
        
        // Create new signature key hash
        bytes32 newSigKeyHash = keccak256(abi.encodePacked(newSignatureKey));
        
        // Create PublicKeys struct for new keys
        PublicKeys memory newKeys = PublicKeys({
            encryptionKey: newEncryptionKey,
            signatureKey: newSignatureKey,
            encryptionKeyHash: newEncKeyHash,
            signatureKeyHash: newSigKeyHash,
            registrationTime: block.timestamp,
            active: true
        });
        
        // Update current keys
        user.currentKeys = newKeys;
        
        // Mark old keys as revoked in history
        if (user.keyHistory[oldEncKeyHash].activationTime > 0) {
            user.keyHistory[oldEncKeyHash].revocationTime = block.timestamp;
            user.keyHistory[oldEncKeyHash].revocationReason = "ROTATED";
            user.keyHistory[oldEncKeyHash].wasRevoked = true;
        }
        
        if (user.keyHistory[oldSigKeyHash].activationTime > 0) {
            user.keyHistory[oldSigKeyHash].revocationTime = block.timestamp;
            user.keyHistory[oldSigKeyHash].revocationReason = "ROTATED";
            user.keyHistory[oldSigKeyHash].wasRevoked = true;
        }
        
        // Add new keys to history
        user.keyHistory[newEncKeyHash] = PublicKeyHistory({
            keyData: newEncryptionKey,
            activationTime: block.timestamp,
            revocationTime: 0,
            revocationReason: "",
            wasRevoked: false
        });
        
        user.keyHistory[newSigKeyHash] = PublicKeyHistory({
            keyData: newSignatureKey,
            activationTime: block.timestamp,
            revocationTime: 0,
            revocationReason: "",
            wasRevoked: false
        });
        
        // Emit key rotation events
        emit KeyRotated(userId, oldEncKeyHash, newEncKeyHash, block.timestamp);
        emit KeyRotated(userId, oldSigKeyHash, newSigKeyHash, block.timestamp);
        
        return true;
    }
    
    /**
     * @dev Revoke a user's keys
     * @param userId ID of the user
     * @param reason Reason for revocation
     * @return success Whether the key revocation was successful
     */
    function revokeKeys(
        string memory userId, 
        string memory reason
    ) external onlyAdmin onlyExistingUser(userId) returns (bool success) {
        // Get user data
        User storage user = users[userId];
        
        // Get the key hashes
        bytes32 encKeyHash = user.currentKeys.encryptionKeyHash;
        bytes32 sigKeyHash = user.currentKeys.signatureKeyHash;
        
        // Mark keys as inactive
        user.currentKeys.active = false;
        
        // Update key history
        if (user.keyHistory[encKeyHash].activationTime > 0) {
            user.keyHistory[encKeyHash].revocationTime = block.timestamp;
            user.keyHistory[encKeyHash].revocationReason = reason;
            user.keyHistory[encKeyHash].wasRevoked = true;
        }
        
        if (user.keyHistory[sigKeyHash].activationTime > 0) {
            user.keyHistory[sigKeyHash].revocationTime = block.timestamp;
            user.keyHistory[sigKeyHash].revocationReason = reason;
            user.keyHistory[sigKeyHash].wasRevoked = true;
        }
        
        // Emit revocation events
        emit KeyRevoked(userId, encKeyHash, block.timestamp, reason);
        emit KeyRevoked(userId, sigKeyHash, block.timestamp, reason);
        
        return true;
    }
    
    /**
     * @dev Get user's current public keys
     * @param userId ID of the user
     * @return encryptionKey The user's encryption public key
     * @return signatureKey The user's signature public key
     * @return isActive Whether the keys are active
     */
    function getUserKeys(string memory userId) external view returns (
        string memory encryptionKey,
        string memory signatureKey,
        bool isActive
    ) {
        require(users[userId].exists, "User does not exist");
        
        return (
            users[userId].currentKeys.encryptionKey,
            users[userId].currentKeys.signatureKey,
            users[userId].currentKeys.active
        );
    }
    
    /**
     * @dev Check if a user exists
     * @param userId ID of the user
     * @return exists Whether the user exists
     */
    function userExists(string memory userId) external view returns (bool exists) {
        return users[userId].exists;
    }
    
    /**
     * @dev Get user's last authentication time
     * @param userId ID of the user
     * @return timestamp The last authentication timestamp
     */
    function getLastAuthentication(string memory userId) external view returns (uint256 timestamp) {
        require(users[userId].exists, "User does not exist");
        return users[userId].lastAuthenticated;
    }
}