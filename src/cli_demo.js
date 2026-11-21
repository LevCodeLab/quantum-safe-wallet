"use strict";

/**
 * quantum-safe-wallet - Terminal Demo (npm run demo)
 * ==================================================
 * Creates an in-memory post-quantum WOTS+/XMSS vault, signs two payloads with
 * monotonic sigSeq one-time keys, verifies the 67-chain WOTS+ and binary XMSS
 * Merkle path, and catches simulated SystemProgram::Assign and SPL::SetAuthority
 * drainer transactions in microseconds.
 */

const crypto = require("crypto");
const {
  VaultCryptoEngine,
  WotsXmssEngine,
  BytecodeDrainerFirewall,
  compileV0MessageFast,
  buildSolTransferIx,
  encodeB58,
  deriveEd25519PublicKeyFromSeed32,
  SYSTEM_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID
} = require("./index");

function randomPubkeyB58() {
  return encodeB58(deriveEd25519PublicKeyFromSeed32(crypto.randomBytes(32)));
}

function runDemo() {
  console.log("========================================================================");
  console.log("  quantum-safe-wallet :: Post-Quantum WOTS+/XMSS + Solana Firewall Demo");
  console.log("========================================================================\n");

  // 1. Create an in-memory post-quantum vault
  const vault = VaultCryptoEngine.createNewVault("CorrectHorseBattery#2026", {
    kdfIterations: 100_000
  });
  const summary = vault.getPublicVaultSummary();

  console.log("[1] Post-Quantum Vault Initialized (AES-256-GCM + PBKDF2-HMAC-SHA512)");
  console.log(`    XMSS Merkle Root      : ${summary.xmssMasterRootHex}`);
  console.log(`    Hash-Locked PDA Vault : ${summary.quantumColdVault.hashLockedQuantumPdaVault}`);
  console.log(`    COLD OTS Address (#0) : ${summary.quantumColdVault.pubkey}`);
  console.log(`    HOT Signing Address   : ${summary.primaryHotWallet.pubkey}\n`);

  // 2. Sign two payloads with strictly monotonic sigSeq and verify 67-chain WOTS+ + XMSS Merkle path
  const blockhashB58 = randomPubkeyB58();
  const recipientB58 = randomPubkeyB58();
  const cleanV0MsgA = compileV0MessageFast(summary.primaryHotWallet.pubkey, blockhashB58, [
    buildSolTransferIx(summary.primaryHotWallet.pubkey, recipientB58, 25_000_000n)
  ]);
  const cleanV0MsgB = compileV0MessageFast(summary.primaryHotWallet.pubkey, blockhashB58, [
    buildSolTransferIx(summary.primaryHotWallet.pubkey, recipientB58, 50_000_000n)
  ]);

  const proof0 = vault.signQuantumProof(320_100_001, cleanV0MsgA);
  const proof1 = vault.signQuantumProof(320_100_001, cleanV0MsgB);

  const verify0 = WotsXmssEngine.verifyTransactionQuantumProof(proof0, cleanV0MsgA, {
    expectedMasterRootHex: summary.xmssMasterRootHex
  });
  const tamperVerify = WotsXmssEngine.verifyTransactionQuantumProof(proof0, cleanV0MsgB, {
    expectedMasterRootHex: summary.xmssMasterRootHex
  });

  console.log("[2] Stateful WOTS+ (w=16, 64 msg + 3 checksum = 67 chains) + XMSS Merkle Proof");
  console.log(`    Proof #0 sigSeq       : ${proof0.sigSeq} -> Proof #1 sigSeq: ${proof1.sigSeq} (never reused)`);
  console.log(`    Signature Wire Size   : ${proof0.wotsWireBytes}B WOTS+ + ${proof0.merklePathBytes}B Merkle path`);
  console.log(`    Pinned Root Verify    : verified=${verify0.verified} (${verify0.authenticity}, ${verify0.verifyLatencyUs} us)`);
  console.log(`    Tampered Msg Verify   : verified=${tamperVerify.verified} (reason=${tamperVerify.reason})\n`);

  // 3. Simulated Drainer #1: SystemProgram::Assign wallet ownership hijack
  const attackerProgramB58 = randomPubkeyB58();
  const assignData = Buffer.allocUnsafe(36);
  assignData.writeUInt32LE(1, 0); // SystemInstruction::Assign = 1
  crypto.randomBytes(32).copy(assignData, 4);

  const assignDrainerTx = compileV0MessageFast(summary.primaryHotWallet.pubkey, blockhashB58, [
    {
      programId: SYSTEM_PROGRAM_ID,
      keys: [{ pubkey: summary.primaryHotWallet.pubkey, isSigner: true, isWritable: true }],
      data: assignData
    }
  ]);

  const assignAudit = BytecodeDrainerFirewall.inspectTransactionBytes(assignDrainerTx, {
    userPubkeyB58: summary.primaryHotWallet.pubkey
  });

  // 4. Simulated Drainer #2: SPL-Token::SetAuthority (AccountOwner = 2) hidden inside ix #1
  const userTokenAtaB58 = randomPubkeyB58();
  const drainerWalletB58 = randomPubkeyB58();
  const setAuthData = Buffer.allocUnsafe(35);
  setAuthData[0] = 6; // TokenInstruction::SetAuthority = 6
  setAuthData[1] = 2; // AuthorityType::AccountOwner = 2
  setAuthData[2] = 1; // COption::Some
  Buffer.from(
    deriveEd25519PublicKeyFromSeed32(crypto.createHash("sha256").update(drainerWalletB58).digest())
  ).copy(setAuthData, 3);

  const setAuthorityDrainerTx = compileV0MessageFast(summary.primaryHotWallet.pubkey, blockhashB58, [
    buildSolTransferIx(summary.primaryHotWallet.pubkey, recipientB58, 1_000_000n),
    {
      programId: SPL_TOKEN_PROGRAM_ID,
      keys: [
        { pubkey: userTokenAtaB58, isSigner: false, isWritable: true },
        { pubkey: summary.primaryHotWallet.pubkey, isSigner: true, isWritable: false }
      ],
      data: setAuthData
    }
  ]);

  const setAuthAudit = BytecodeDrainerFirewall.inspectTransactionBytes(setAuthorityDrainerTx, {
    userPubkeyB58: summary.primaryHotWallet.pubkey,
    userTokenAtas: [userTokenAtaB58]
  });

  // 5. Clean SOL transfer audit
  const cleanAudit = BytecodeDrainerFirewall.inspectTransactionBytes(cleanV0MsgA, {
    userPubkeyB58: summary.primaryHotWallet.pubkey
  });

  console.log("[3] Static Binary Solana Transaction Firewall (<150us Zero-RPC Decode)");
  console.log(
    `    SystemProgram::Assign : safe=${assignAudit.safe} | ${assignAudit.ruleTriggered} (${assignAudit.inspectLatencyUs} us)`
  );
  console.log(
    `    SPL::SetAuthority     : safe=${setAuthAudit.safe} | ${setAuthAudit.ruleTriggered} (${setAuthAudit.inspectLatencyUs} us)`
  );
  console.log(
    `    Clean 0.025 SOL Send  : safe=${cleanAudit.safe}  | ${cleanAudit.tier} (${cleanAudit.inspectLatencyUs} us)\n`
  );

  vault.lockAndDestroy();
  console.log("Vault locked and secret key buffers zeroized.");
}

runDemo();
