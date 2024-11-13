// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "./IdentityRegistry.sol";

contract SessionManager {
    struct Session {
        bytes32 sessionId;
        string did;
        uint256 timestamp;
        uint256 expiresAt;
        bool active;
    }

    IdentityRegistry private identityRegistry;
    
    mapping(bytes32 => Session) private sessions;
    mapping(string => bytes32) private activeSessions;

    uint256 public constant SESSION_DURATION = 24 hours;

    event SessionCreated(bytes32 indexed sessionId, string did);
    event SessionRevoked(bytes32 indexed sessionId, string did);

    error SessionNotFound(bytes32 sessionId);
    error SessionExpired(bytes32 sessionId);
    error InvalidDID(string did);
    error SessionAlreadyExists(string did);
    error NotAuthorized();

    constructor(address _identityRegistryAddress) {
        identityRegistry = IdentityRegistry(_identityRegistryAddress);
    }

    function createSession(string calldata did) external returns (bytes32) {
        if (!identityRegistry.isValidDID(did)) revert InvalidDID(did);
        if (activeSessions[did] != bytes32(0)) revert SessionAlreadyExists(did);

        bytes32 sessionId = generateSessionId(did);
        uint256 expirationTime = block.timestamp + SESSION_DURATION;

        Session memory newSession = Session({
            sessionId: sessionId,
            did: did,
            timestamp: block.timestamp,
            expiresAt: expirationTime,
            active: true
        });

        sessions[sessionId] = newSession;
        activeSessions[did] = sessionId;

        emit SessionCreated(sessionId, did);
        return sessionId;
    }

    function revokeSession(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];
        if (session.sessionId == bytes32(0)) revert SessionNotFound(sessionId);

        if (!isSessionOwner(session.did, msg.sender)) revert NotAuthorized();

        session.active = false;
        activeSessions[session.did] = bytes32(0);

        emit SessionRevoked(sessionId, session.did);
    }

    function validateSession(bytes32 sessionId) external view returns (bool) {
        Session memory session = sessions[sessionId];
        if (session.sessionId == bytes32(0)) return false;
        
        return session.active && block.timestamp <= session.expiresAt;
    }

    function getSession(bytes32 sessionId) external view returns (Session memory) {
        Session memory session = sessions[sessionId];
        if (session.sessionId == bytes32(0)) revert SessionNotFound(sessionId);
        return session;
    }

    function generateSessionId(string memory did) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(did, block.timestamp, msg.sender));
    }

    function isSessionOwner(string memory did, address caller) internal view returns (bool) {
        return msg.sender == identityRegistry.getDidAddress(did);
    }
}