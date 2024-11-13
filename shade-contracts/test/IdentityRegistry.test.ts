import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

describe("IdentityRegistry", function () {
  async function deployIdentityRegistryFixture() {
    const [owner, otherAccount] = await ethers.getSigners();
    const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry");
    const registry = await IdentityRegistry.deploy();

    const mockDID = `did:eth:${owner.address}`;
    const mockPublicKey = ethers.randomBytes(33);

    return { registry, owner, otherAccount, mockDID, mockPublicKey };
  }

  describe("DID Registration", function () {
    it("Should register a new DID", async function () {
      const { registry, mockDID, mockPublicKey } = await loadFixture(deployIdentityRegistryFixture);

      await expect(registry.registerDID(mockDID, mockPublicKey))
        .to.emit(registry, "DIDRegistered")
        .withArgs(mockDID, (await (await ethers.provider.getSigner()).getAddress()));
    });

    it("Should revert when registering with empty DID", async function () {
      const { registry, mockPublicKey } = await loadFixture(deployIdentityRegistryFixture);

      await expect(registry.registerDID("", mockPublicKey))
        .to.be.revertedWithCustomError(registry, "DIDCannotBeEmpty");
    });

    it("Should revert when registering with empty public key", async function () {
      const { registry, mockDID } = await loadFixture(deployIdentityRegistryFixture);

      await expect(registry.registerDID(mockDID, "0x"))
        .to.be.revertedWithCustomError(registry, "PublicKeyCannotBeEmpty");
    });

    it("Should revert when DID is already registered", async function () {
      const { registry, mockDID, mockPublicKey } = await loadFixture(deployIdentityRegistryFixture);

      await registry.registerDID(mockDID, mockPublicKey);
      await expect(registry.registerDID(mockDID, mockPublicKey))
        .to.be.revertedWithCustomError(registry, "DIDAlreadyRegistered");
    });

    it("Should revert when DID is taken by another address", async function () {
      const { registry, mockDID, mockPublicKey, otherAccount } = await loadFixture(deployIdentityRegistryFixture);

      await registry.registerDID(mockDID, mockPublicKey);
      await expect(registry.connect(otherAccount).registerDID(mockDID, mockPublicKey))
        .to.be.revertedWithCustomError(registry, "DIDAlreadyExists");
    });
  });

  describe("DID Deactivation", function () {
    it("Should deactivate a DID", async function () {
      const { registry, mockDID, mockPublicKey } = await loadFixture(deployIdentityRegistryFixture);

      await registry.registerDID(mockDID, mockPublicKey);
      await expect(registry.deactivateDID(mockDID))
        .to.emit(registry, "DIDDeactivated")
        .withArgs(mockDID, await (await ethers.provider.getSigner()).getAddress());
    });

    it("Should revert when deactivating non-existent DID", async function () {
      const { registry, mockDID } = await loadFixture(deployIdentityRegistryFixture);

      await expect(registry.deactivateDID(mockDID))
        .to.be.revertedWithCustomError(registry, "NotAuthorized");
    });
  });

  describe("DID Validation", function () {
    it("Should validate an active DID", async function () {
      const { registry, mockDID, mockPublicKey } = await loadFixture(deployIdentityRegistryFixture);

      await registry.registerDID(mockDID, mockPublicKey);
      expect(await registry.isValidDID(mockDID)).to.be.true;
    });

    it("Should return false for deactivated DID", async function () {
      const { registry, mockDID, mockPublicKey } = await loadFixture(deployIdentityRegistryFixture);

      await registry.registerDID(mockDID, mockPublicKey);
      await registry.deactivateDID(mockDID);
      expect(await registry.isValidDID(mockDID)).to.be.false;
    });
  });
});