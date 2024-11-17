// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract IdentityRegistry {
    struct DIDDocument {
        string did;
        string publicKey;
        uint256 timestamp;
        bool active;
    }

    mapping(address => DIDDocument) private identities;
    mapping(string => address) private didToAddress;

    event DIDRegistered(string did, address indexed owner);
    event DIDDeactivated(string did, address indexed owner);

    error DIDAlreadyExists(string did);
    error DIDAlreadyRegistered(address owner);
    error DIDAlreadyDeactivated(address owner);
    error DIDCannotBeEmpty();
    error PublicKeyCannotBeEmpty();
    error NotAuthorized();
    error DIDNotFound(string did);

    function registerDID(string calldata did, string calldata publicKey) external {
        if (bytes(did).length == 0) revert DIDCannotBeEmpty();
        if (bytes(publicKey).length == 0) revert PublicKeyCannotBeEmpty();
        if (identities[msg.sender].timestamp != 0) revert DIDAlreadyRegistered(msg.sender);
        if (didToAddress[did] != address(0)) revert DIDAlreadyExists(did);

        DIDDocument memory newIdentity = DIDDocument({
            did: did,
            publicKey: publicKey,
            timestamp: block.timestamp,
            active: true
        });

        identities[msg.sender] = newIdentity;
        didToAddress[did] = msg.sender;

        emit DIDRegistered(did, msg.sender);
    }

    function deactivateDID(string calldata did) external {
        if (didToAddress[did] != msg.sender) revert NotAuthorized();
        if (!identities[msg.sender].active) revert DIDAlreadyDeactivated(msg.sender);

        identities[msg.sender].active = false;
        emit DIDDeactivated(did, msg.sender);
    }

    function getDIDDocument(string calldata did) external view returns (DIDDocument memory) {
        address owner = didToAddress[did];
        if (owner == address(0)) revert DIDNotFound(did);
        return identities[owner];
    }

    function isValidDID(string calldata did) external view returns (bool) {
        address owner = didToAddress[did];
        return owner != address(0) && identities[owner].active;
    }

    function getIdentity(address owner) external view returns (DIDDocument memory) {
        return identities[owner];
    }

    function getDidAddress(string calldata did) external view returns (address) {
        return didToAddress[did];
    }
}