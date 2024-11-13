// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const AuthModule = buildModule("AuthModule", (m) => {
  const IdentityRegistry = m.contract("IdentityRegistry");

  const sessionManager = m.contract("SessionManager");

  return { IdentityRegistry, sessionManager };
});

export default AuthModule;
