import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

describe("SessionManager", function () {
  async function deploySessionManagerFixture() {
    const [owner, otherAccount] = await ethers.getSigners();
    
    const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry");
    const registry = await IdentityRegistry.deploy();

    const SessionManager = await ethers.getContractFactory("SessionManager");
    const sessionManager = await SessionManager.deploy(await registry.getAddress());

    const mockDID = `did:eth:${owner.address}`;
    const mockPublicKey = ethers.randomBytes(33);

    await registry.registerDID(mockDID, mockPublicKey);

    return { sessionManager, registry, owner, otherAccount, mockDID };
  }

  describe("Session Creation", function () {
    it("Should create a new session", async function () {
      const { sessionManager, mockDID } = await loadFixture(deploySessionManagerFixture);

      await expect(sessionManager.createSession(mockDID))
        .to.emit(sessionManager, "SessionCreated");
    });

    it("Should revert when creating session for invalid DID", async function () {
      const { sessionManager } = await loadFixture(deploySessionManagerFixture);

      await expect(sessionManager.createSession("did:eth:invalid"))
        .to.be.revertedWithCustomError(sessionManager, "InvalidDID");
    });

    it("Should revert when creating duplicate session", async function () {
      const { sessionManager, mockDID } = await loadFixture(deploySessionManagerFixture);

      await sessionManager.createSession(mockDID);
      await expect(sessionManager.createSession(mockDID))
        .to.be.revertedWithCustomError(sessionManager, "SessionAlreadyExists");
    });
  });

  describe("Session Validation", function () {
    it("Should validate active session", async function () {
      const { sessionManager, mockDID } = await loadFixture(deploySessionManagerFixture);

      const tx = await sessionManager.createSession(mockDID);
      const receipt = await tx.wait();
      const event = receipt?.logs[0];
      const sessionId = event?.topics[1];

      expect(await sessionManager.validateSession(sessionId!)).to.be.true;
    });

    it("Should invalidate expired session", async function () {
      const { sessionManager, mockDID } = await loadFixture(deploySessionManagerFixture);

      const tx = await sessionManager.createSession(mockDID);
      const receipt = await tx.wait();
      const event = receipt?.logs[0];
      const sessionId = event?.topics[1];

      await time.increase(24 * 60 * 60 + 1);

      expect(await sessionManager.validateSession(sessionId!)).to.be.false;
    });
  });

  describe("Session Revocation", function () {
    it("Should revoke active session", async function () {
      const { sessionManager, mockDID } = await loadFixture(deploySessionManagerFixture);

      const tx = await sessionManager.createSession(mockDID);
      const receipt = await tx.wait();
      const event = receipt?.logs[0];
      const sessionId = event?.topics[1];

      await expect(sessionManager.revokeSession(sessionId!))
        .to.emit(sessionManager, "SessionRevoked");
    });

    it("Should revert when revoking non-existent session", async function () {
      const { sessionManager } = await loadFixture(deploySessionManagerFixture);

      const fakeSessionId = ethers.randomBytes(32);
      await expect(sessionManager.revokeSession(fakeSessionId))
        .to.be.revertedWithCustomError(sessionManager, "SessionNotFound");
    });
  });
});