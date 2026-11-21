"use strict";

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const {
  VaultCryptoEngine,
  WotsXmssEngine,
  BytecodeDrainerFirewall,
  startWalletHttpServer,
  AUTH_HEADER_NAME,
  compileV0MessageFast,
  encodeCompactU16,
  buildSolTransferIx,
  buildSplTransferCheckedIx,
  buildSetComputeUnitLimitIx,
  buildSetComputeUnitPriceIx,
  guardAndSignTransaction,
  deriveHashLockedQuantumPdaVault,
  encodeB58,
  decodeB58,
  deriveEd25519PublicKeyFromSeed32,
  signEd25519Seed32Native,
  verifyEd25519Native,
  WOTS_TOTAL_CHAINS,
  QSAFE_PQ_VAULT_PROGRAM_ID_B58,
  SYSTEM_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID
} = require("../src");

function randomPubkeyB58() {
  return encodeB58(deriveEd25519PublicKeyFromSeed32(crypto.randomBytes(32)));
}

function rawHttpPost(url, bodyObj, customHeaders = {}) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(bodyObj);
    const parsed = new URL(url);
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: "/",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
          ...customHeaders
        }
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (_) {}
          resolve({ statusCode: res.statusCode, json, text });
        });
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

describe("Post-Quantum WOTS+/XMSS Engine & Encrypted Key Vault", () => {
  let tmpDir;

  before(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "qsafe-vault-test-"));
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("signs and verifies 67-chain WOTS+ + XMSS Merkle proofs with monotonic sigSeq", () => {
    const engine = new WotsXmssEngine(crypto.randomBytes(32), 0);
    const msgA = Buffer.from("solana-v0-payload-alpha");
    const msgB = Buffer.from("solana-v0-payload-beta");

    const proofA = engine.signTransactionQuantumProof(320_000_001, msgA);
    const proofB = engine.signTransactionQuantumProof(320_000_001, msgB);

    assert.equal(proofA.sigSeq, 0);
    assert.equal(proofB.sigSeq, 1);
    assert.notEqual(proofA.wotsPublicRootHex, proofB.wotsPublicRootHex);
    assert.equal(proofA.wotsChainElementsHex.length, WOTS_TOTAL_CHAINS);
    assert.equal(proofA.wotsWireBytes, 2144);
    assert.equal(proofA.merkleAuthPathHex.length, 4);
    assert.equal(proofA.merklePathBytes, 128);

    const validCheck = WotsXmssEngine.verifyTransactionQuantumProof(proofA, msgA, {
      expectedMasterRootHex: engine.masterRootHex
    });
    assert.equal(validCheck.verified, true);
    assert.equal(validCheck.authenticity, "PINNED_XMSS_MERKLE_ROOT");

    // Reject tampered message against same signature
    const tamperCheck = WotsXmssEngine.verifyTransactionQuantumProof(proofA, msgB, {
      expectedMasterRootHex: engine.masterRootHex
    });
    assert.equal(tamperCheck.verified, false);

    // Reject single-bit tampered WOTS+ chain element
    const mutatedProof = JSON.parse(JSON.stringify(proofA));
    mutatedProof.wotsChainElementsHex[12] = "ff".repeat(32);
    const chainTamperCheck = WotsXmssEngine.verifyTransactionQuantumProof(mutatedProof, msgA, {
      expectedMasterRootHex: engine.masterRootHex
    });
    assert.equal(chainTamperCheck.verified, false);

    // Reject proof generated from a foreign XMSS master tree when root is pinned
    const foreignEngine = new WotsXmssEngine(crypto.randomBytes(32), 0);
    const foreignProof = foreignEngine.signTransactionQuantumProof(320_000_001, msgA);
    const foreignCheck = WotsXmssEngine.verifyTransactionQuantumProof(foreignProof, msgA, {
      expectedMasterRootHex: engine.masterRootHex
    });
    assert.equal(foreignCheck.verified, false);
    assert.equal(foreignCheck.reason, "PINNED_MASTER_ROOT_MISMATCH");

    // Reject OTS replay below minAcceptedSigSeq watermark
    const replayCheck = WotsXmssEngine.verifyTransactionQuantumProof(proofA, msgA, {
      expectedMasterRootHex: engine.masterRootHex,
      minAcceptedSigSeq: 1
    });
    assert.equal(replayCheck.verified, false);
    assert.equal(replayCheck.reason, "OTS_SIGSEQ_REPLAY_REJECTED");

    engine.destroy();
    foreignEngine.destroy();
  });

  it("derives Shor-immune SHA-256 hash-locked PDA distinct from Ed25519 cold address", () => {
    const vault = VaultCryptoEngine.createNewVault("StrongVaultPass#2026!", {
      kdfIterations: 100_000
    });
    const summary = vault.getPublicVaultSummary();
    assert.equal(summary.quantumColdVault.programId, QSAFE_PQ_VAULT_PROGRAM_ID_B58);
    assert.equal(
      summary.quantumColdVault.pdaVaultQuantumModel,
      "SHOR_IMMUNE_HASH_LOCKED_PDA_NO_ED25519_KEY"
    );
    assert.notEqual(
      summary.quantumColdVault.hashLockedQuantumPdaVault,
      summary.quantumColdVault.pubkey
    );

    const recomputedPda = deriveHashLockedQuantumPdaVault(summary.xmssMasterRootHex, 0);
    assert.equal(recomputedPda.pdaAddressB58, summary.quantumColdVault.hashLockedQuantumPdaVault);
    vault.lockAndDestroy();
  });

  it("enforces >=10 char passphrase, path traversal sandbox, symlink block, and state MAC", async () => {
    assert.throws(
      () => VaultCryptoEngine.createNewVault("short123", { kdfIterations: 100_000 }),
      /RULE_11_WEAK_PASSPHRASE/
    );

    assert.throws(
      () =>
        VaultCryptoEngine.createNewVault("StrongVaultPass#2026!", {
          vaultFilePath: "/etc/forbidden_qsafe_vault.json",
          kdfIterations: 100_000
        }),
      /SECURITY_PATH_TRAVERSAL_BLOCKED/
    );

    const vaultPath = path.join(tmpDir, "vault.json");
    const created = await VaultCryptoEngine.createNewVaultAsync("StrongVaultPass#2026!", {
      vaultFilePath: vaultPath,
      kdfIterations: 100_000
    });
    const expectedHotPub = created.getPublicVaultSummary().primaryHotWallet.pubkey;
    created.signQuantumProof(100, Buffer.from("reserve-seq-window"));
    created.lockAndDestroy();

    // Refuse accidental overwrite without allowOverwrite=true
    assert.throws(
      () =>
        VaultCryptoEngine.createNewVault("StrongVaultPass#2026!", {
          vaultFilePath: vaultPath,
          kdfIterations: 100_000
        }),
      /VAULT_FILE_ALREADY_EXISTS/
    );

    // Reject symlink vault access
    const symlinkPath = path.join(tmpDir, "symlink_vault.json");
    fs.symlinkSync(vaultPath, symlinkPath);
    assert.throws(
      () => VaultCryptoEngine.loadVault(symlinkPath, "StrongVaultPass#2026!"),
      /SECURITY_SYMLINK_BLOCKED/
    );

    // Reload encrypted vault and verify reserved sigSeq watermark persisted
    const reloaded = await VaultCryptoEngine.loadVaultAsync(vaultPath, "StrongVaultPass#2026!");
    assert.equal(reloaded.getPublicVaultSummary().primaryHotWallet.pubkey, expectedHotPub);
    assert.ok(reloaded.xmssEngine.sigSeqCounter >= 1024);
    reloaded.lockAndDestroy();

    // Detect plaintext state tampering via HMAC-SHA256 stateMacHex
    const rawEnvelope = JSON.parse(fs.readFileSync(vaultPath, "utf8"));
    rawEnvelope.state.quantumColdVaultPubkey = randomPubkeyB58();
    assert.throws(
      () => VaultCryptoEngine.loadVault(rawEnvelope, "StrongVaultPass#2026!"),
      /VAULT_STATE_TAMPERED/
    );
  });
});

describe("10-Rule Static Binary Solana Drainer Firewall", () => {
  const userWallet = randomPubkeyB58();
  const userAta = randomPubkeyB58();
  const attackerPubkey = randomPubkeyB58();
  const blockhash = randomPubkeyB58();

  it("blocks RULE_01 SystemProgram::Assign and unverified CreateAccount hijacks", () => {
    const assignData = Buffer.allocUnsafe(36);
    assignData.writeUInt32LE(1, 0);
    decodeB58(attackerPubkey).copy(assignData, 4);

    const assignTx = compileV0MessageFast(userWallet, blockhash, [
      {
        programId: SYSTEM_PROGRAM_ID,
        keys: [{ pubkey: userWallet, isSigner: true, isWritable: true }],
        data: assignData
      }
    ]);
    const res1 = BytecodeDrainerFirewall.inspectTransactionBytes(assignTx, {
      userPubkeyB58: userWallet
    });
    assert.equal(res1.safe, false);
    assert.equal(res1.ruleTriggered, "RULE_01_NO_SYSTEM_ASSIGN");

    const createData = Buffer.allocUnsafe(52);
    createData.writeUInt32LE(0, 0);
    createData.writeBigUInt64LE(10_000_000n, 4);
    createData.writeBigUInt64LE(165n, 12);
    decodeB58(attackerPubkey).copy(createData, 20);

    const createTx = compileV0MessageFast(userWallet, blockhash, [
      {
        programId: SYSTEM_PROGRAM_ID,
        keys: [
          { pubkey: userWallet, isSigner: true, isWritable: true },
          { pubkey: randomPubkeyB58(), isSigner: true, isWritable: true }
        ],
        data: createData
      }
    ]);
    const res2 = BytecodeDrainerFirewall.inspectTransactionBytes(createTx, {
      userPubkeyB58: userWallet
    });
    assert.equal(res2.safe, false);
    assert.equal(res2.ruleTriggered, "RULE_01_CREATE_ACCOUNT_UNVERIFIED_OWNER");
  });

  it("blocks RULE_02 SPL SetAuthority, unauthorized direct Transfer, and Token-2022 Burn", () => {
    const setAuthData = Buffer.allocUnsafe(35);
    setAuthData[0] = 6; // SetAuthority
    setAuthData[1] = 2; // AccountOwner
    setAuthData[2] = 1; // Some
    decodeB58(attackerPubkey).copy(setAuthData, 3);

    const setAuthTx = compileV0MessageFast(userWallet, blockhash, [
      {
        programId: SPL_TOKEN_PROGRAM_ID,
        keys: [
          { pubkey: userAta, isSigner: false, isWritable: true },
          { pubkey: userWallet, isSigner: true, isWritable: false }
        ],
        data: setAuthData
      }
    ]);
    const authRes = BytecodeDrainerFirewall.inspectTransactionBytes(setAuthTx, {
      userPubkeyB58: userWallet,
      userTokenAtas: [userAta]
    });
    assert.equal(authRes.safe, false);
    assert.equal(authRes.ruleTriggered, "RULE_02_NO_SET_AUTHORITY");

    const transferTx = compileV0MessageFast(userWallet, blockhash, [
      buildSplTransferCheckedIx({
        sourceAtaB58: userAta,
        mintB58: randomPubkeyB58(),
        destinationAtaB58: randomPubkeyB58(),
        ownerPubkeyB58: userWallet,
        amount: 500_000n,
        decimals: 6
      })
    ]);
    const transferRes = BytecodeDrainerFirewall.inspectTransactionBytes(transferTx, {
      userPubkeyB58: userWallet,
      userTokenAtas: [userAta]
    });
    assert.equal(transferRes.safe, false);
    assert.equal(transferRes.ruleTriggered, "RULE_02B_UNAUTHORIZED_TOKEN_TRANSFER");

    const burnData = Buffer.allocUnsafe(10);
    burnData[0] = 15; // BurnChecked
    burnData.writeBigUInt64LE(100_000n, 1);
    burnData[9] = 6;
    const burnTx = compileV0MessageFast(userWallet, blockhash, [
      {
        programId: TOKEN_2022_PROGRAM_ID,
        keys: [
          { pubkey: userAta, isSigner: false, isWritable: true },
          { pubkey: randomPubkeyB58(), isSigner: false, isWritable: true },
          { pubkey: userWallet, isSigner: true, isWritable: false }
        ],
        data: burnData
      }
    ]);
    const burnRes = BytecodeDrainerFirewall.inspectTransactionBytes(burnTx, {
      userPubkeyB58: userWallet,
      userTokenAtas: [userAta]
    });
    assert.equal(burnRes.safe, false);
    assert.equal(burnRes.ruleTriggered, "RULE_02C_UNAUTHORIZED_TOKEN_BURN");
  });

  it("blocks RULE_03 unknown CPI quarantine and unresolved V0 ALT lookups", () => {
    const unknownProg = randomPubkeyB58();
    const cpiTx = compileV0MessageFast(userWallet, blockhash, [
      {
        programId: unknownProg,
        keys: [
          { pubkey: userWallet, isSigner: true, isWritable: true },
          { pubkey: randomPubkeyB58(), isSigner: false, isWritable: true }
        ],
        data: Buffer.from([1, 2, 3, 4])
      }
    ]);
    const cpiRes = BytecodeDrainerFirewall.inspectTransactionBytes(cpiTx, {
      userPubkeyB58: userWallet,
      allowExternalDappWithGuard: false
    });
    assert.equal(cpiRes.safe, false);
    assert.equal(cpiRes.ruleTriggered, "RULE_03_UNKNOWN_CPI_WRITABLE_QUARANTINE");

    const altTableKey = randomPubkeyB58();
    const hiddenAcc = randomPubkeyB58();
    const altTx = compileV0MessageFast(
      userWallet,
      blockhash,
      [buildSolTransferIx(userWallet, hiddenAcc, 1000n)],
      [{ tableKeyB58: altTableKey, addressesB58: [hiddenAcc] }]
    );

    const unresolvedAlt = BytecodeDrainerFirewall.inspectTransactionBytes(altTx, {
      userPubkeyB58: userWallet
    });
    assert.equal(unresolvedAlt.safe, false);
    assert.equal(unresolvedAlt.ruleTriggered, "RULE_03B_UNRESOLVED_ALT_ACCOUNT");

    const resolvedAlt = BytecodeDrainerFirewall.inspectTransactionBytes(altTx, {
      userPubkeyB58: userWallet,
      altLookupMap: new Map([[altTableKey, [hiddenAcc]]])
    });
    assert.equal(resolvedAlt.safe, true);
  });

  it("blocks RULE_04 AdvanceNonceAccount, RULE_05 signMessage phishing, and RULE_06 Approve", () => {
    // RULE_04: AdvanceNonceAccount (4)
    const nonceData = Buffer.allocUnsafe(4);
    nonceData.writeUInt32LE(4, 0);
    const nonceTx = compileV0MessageFast(userWallet, blockhash, [
      {
        programId: SYSTEM_PROGRAM_ID,
        keys: [
          { pubkey: randomPubkeyB58(), isSigner: false, isWritable: true },
          { pubkey: randomPubkeyB58(), isSigner: false, isWritable: false },
          { pubkey: userWallet, isSigner: true, isWritable: false }
        ],
        data: nonceData
      }
    ]);
    const nonceRes = BytecodeDrainerFirewall.inspectTransactionBytes(nonceTx, {
      userPubkeyB58: userWallet
    });
    assert.equal(nonceRes.safe, false);
    assert.equal(nonceRes.ruleTriggered, "RULE_04_NO_EXTERNAL_DURABLE_NONCE");

    // RULE_05: signMessage raw V0 TransactionMessage phishing vs genuine UTF-8 text
    const disguisedV0 = compileV0MessageFast(userWallet, blockhash, [
      buildSolTransferIx(userWallet, attackerPubkey, 1_000_000_000n)
    ]);
    const phishingCheck = BytecodeDrainerFirewall.inspectSignMessagePayload(disguisedV0, userWallet);
    assert.equal(phishingCheck.safe, false);
    assert.equal(phishingCheck.ruleTriggered, "RULE_05_SIGN_MESSAGE_TX_BITFLIP");

    const safeMsgCheck = BytecodeDrainerFirewall.inspectSignMessagePayload(
      "Sign in to Demo App #42",
      userWallet
    );
    assert.equal(safeMsgCheck.safe, true);
    assert.equal(
      safeMsgCheck.domainSeparatedPayload.subarray(0, 16).toString("binary"),
      "\xffsolana offchain"
    );

    // RULE_06: SPL Approve (4) + Revoke builder
    const approveData = Buffer.allocUnsafe(9);
    approveData[0] = 4;
    approveData.writeBigUInt64LE(18_446_744_073_709_551_615n, 1);
    const approveTx = compileV0MessageFast(userWallet, blockhash, [
      {
        programId: SPL_TOKEN_PROGRAM_ID,
        keys: [
          { pubkey: userAta, isSigner: false, isWritable: true },
          { pubkey: attackerPubkey, isSigner: false, isWritable: false },
          { pubkey: userWallet, isSigner: true, isWritable: false }
        ],
        data: approveData
      }
    ]);
    const approveRes = BytecodeDrainerFirewall.inspectTransactionBytes(approveTx, {
      userPubkeyB58: userWallet
    });
    assert.equal(approveRes.safe, false);
    assert.equal(approveRes.ruleTriggered, "RULE_06_NO_TOKEN_DELEGATE");

    const revokeIx = BytecodeDrainerFirewall.buildRevokeDelegateIx(userAta, userWallet);
    assert.equal(revokeIx.data[0], 5);
  });

  it("blocks RULE_07 Token-2022 TLV traps, RULE_08 CloseAccount & priority fee drain, and RULE_09 poisoning", () => {
    // RULE_07: Token-2022 PermanentDelegate (type=12) TLV extension
    const mintBuf = Buffer.alloc(166 + 4 + 32, 0);
    mintBuf[165] = 1; // AccountType::Mint
    mintBuf.writeUInt16LE(12, 166); // ExtensionType::PermanentDelegate = 12
    mintBuf.writeUInt16LE(32, 168);
    decodeB58(attackerPubkey).copy(mintBuf, 170);

    const tlvAudit = BytecodeDrainerFirewall.auditToken2022MintAccountData(mintBuf);
    assert.equal(tlvAudit.safe, false);
    assert.equal(tlvAudit.findings[0].rule, "RULE_07_PERMANENT_DELEGATE_TRAP");

    // RULE_08: CloseAccount rent redirect to external attacker
    const closeRentStealTx = compileV0MessageFast(userWallet, blockhash, [
      {
        programId: SPL_TOKEN_PROGRAM_ID,
        keys: [
          { pubkey: userAta, isSigner: false, isWritable: true },
          { pubkey: attackerPubkey, isSigner: false, isWritable: true },
          { pubkey: userWallet, isSigner: true, isWritable: false }
        ],
        data: Buffer.from([9])
      }
    ]);
    const closeRes = BytecodeDrainerFirewall.inspectTransactionBytes(closeRentStealTx, {
      userPubkeyB58: userWallet,
      userTokenAtas: [userAta]
    });
    assert.equal(closeRes.safe, false);
    assert.equal(closeRes.ruleTriggered, "RULE_08_CLOSE_ACCOUNT_RENT_STEAL");

    // RULE_08: Excessive priority fee burn
    const prioDrainTx = compileV0MessageFast(userWallet, blockhash, [
      buildSetComputeUnitLimitIx(1_000_000),
      buildSetComputeUnitPriceIx(500_000_000n), // 0.5 SOL priority fee > 0.1 SOL cap
      buildSolTransferIx(userWallet, userWallet, 1000n)
    ]);
    const prioRes = BytecodeDrainerFirewall.inspectTransactionBytes(prioDrainTx, {
      userPubkeyB58: userWallet
    });
    assert.equal(prioRes.safe, false);
    assert.equal(prioRes.ruleTriggered, "RULE_08_EXCESSIVE_PRIORITY_FEE");

    // RULE_09: Vanity prefix/suffix lookalike poisoning
    const trustedVault = randomPubkeyB58();
    const poisonedLookalike =
      trustedVault.slice(0, 4) +
      "999999999999999999999999999999999999" +
      trustedVault.slice(-4);
    const poisonCheck = BytecodeDrainerFirewall.inspectAddressPoisoningRisk(poisonedLookalike, [
      trustedVault
    ]);
    assert.equal(poisonCheck.safe, false);
    assert.equal(poisonCheck.poisoningDetected, true);
    assert.equal(poisonCheck.ruleTriggered, "RULE_09_VANITY_ADDRESS_POISONING");
  });

  it("injects RULE_10 On-Chain Balance-Floor Guard and preserves multi-signer co-signatures", () => {
    const vault = VaultCryptoEngine.createNewVault("StrongVaultPass#2026!", {
      kdfIterations: 100_000
    });
    const hotPubkey = vault.getPublicVaultSummary().primaryHotWallet.pubkey;
    const unknownProg = randomPubkeyB58();

    const unverifiedMsg = compileV0MessageFast(hotPubkey, blockhash, [
      {
        programId: unknownProg,
        keys: [
          { pubkey: hotPubkey, isSigner: true, isWritable: true },
          { pubkey: randomPubkeyB58(), isSigner: false, isWritable: true }
        ],
        data: Buffer.from([7, 8, 9])
      }
    ]);

    assert.throws(
      () =>
        guardAndSignTransaction(vault, unverifiedMsg, {
          tier: "HOT",
          allowExternalDappWithGuard: true
        }),
      /EXPLICIT_VERIFIED_BALANCE_REQUIRED/
    );

    const guarded = guardAndSignTransaction(vault, unverifiedMsg, {
      tier: "HOT",
      slot: 320_000_010,
      currentWalletBalanceLamports: 5_000_000_000n,
      maxApprovedSolLamports: 500_000_000n,
      userTokenAtas: [userAta],
      protectedTokenAtas: [
        { ataPubkeyB58: userAta, minRemainingRawAmount: 1_000_000n, isToken2022: false }
      ],
      allowExternalDappWithGuard: true
    });
    assert.equal(guarded.status, "GUARDED_AND_SIGNED");
    assert.equal(guarded.onChainBalanceFloorGuardAttached, true);
    assert.equal(guarded.roundTripGuardActive, true);
    assert.ok(guarded.balanceFloorInvariant.includes("4499950000 lamports"));

    // Multi-signer canonical transaction co-signature preservation
    const coSeed = crypto.randomBytes(32);
    const coPub32 = deriveEd25519PublicKeyFromSeed32(coSeed);
    const coPubB58 = encodeB58(coPub32);

    const multiMsg = compileV0MessageFast(hotPubkey, blockhash, [
      {
        programId: SYSTEM_PROGRAM_ID,
        keys: [
          { pubkey: hotPubkey, isSigner: true, isWritable: true },
          { pubkey: coPubB58, isSigner: true, isWritable: true }
        ],
        data: buildSolTransferIx(hotPubkey, coPubB58, 10_000n).data
      }
    ]);
    const coSig64 = signEd25519Seed32Native(coSeed, multiMsg);
    const partialWire = Buffer.concat([encodeCompactU16(2), Buffer.alloc(64, 0), coSig64, multiMsg]);

    const multiSigned = guardAndSignTransaction(vault, partialWire, { tier: "HOT" });
    assert.equal(multiSigned.status, "GUARDED_AND_SIGNED");
    assert.equal(multiSigned.multiSignerPreserved, true);
    const sig0 = multiSigned.wireTransaction.subarray(1, 65);
    const sig1 = multiSigned.wireTransaction.subarray(65, 129);
    const signedMsg = multiSigned.wireTransaction.subarray(129);
    assert.equal(verifyEd25519Native(decodeB58(hotPubkey), signedMsg, sig0), true);
    assert.equal(verifyEd25519Native(coPub32, signedMsg, sig1), true);

    vault.lockAndDestroy();
  });

  it("fails closed on 500 random malformed wire buffers with zero uncaught exceptions", () => {
    let blockedCount = 0;
    for (let i = 0; i < 500; i++) {
      const buf = crypto.randomBytes((i % 160) + 1);
      const res = BytecodeDrainerFirewall.inspectTransactionBytes(buf, {
        userPubkeyB58: userWallet
      });
      if (!res.safe) blockedCount++;
    }
    assert.equal(blockedCount, 500);
  });
});

describe("Loopback JSON-RPC 2.0 Server Auth, Rate-Limit & COLD/HOT Tier Policy", () => {
  let daemon;

  before(async () => {
    daemon = await startWalletHttpServer({
      port: 0,
      maxFailedUnlockAttempts: 3,
      unlockLockoutDurationMs: 5000,
      kdfIterations: 100_000
    });
  });

  after(async () => {
    await daemon.close();
  });

  it("enforces X-QSafe-Auth-Token, Host DNS-rebinding block, and Origin check", async () => {
    const noToken = await rawHttpPost(daemon.url, {
      jsonrpc: "2.0",
      id: 1,
      method: "wallet_createVault",
      params: { passphrase: "StrongVaultPass#2026!" }
    });
    assert.equal(noToken.statusCode, 401);

    const badOrigin = await rawHttpPost(
      daemon.url,
      { jsonrpc: "2.0", id: 2, method: "wallet_connect", params: {} },
      {
        [AUTH_HEADER_NAME]: daemon.authToken,
        Origin: "https://phishing-dapp.example"
      }
    );
    assert.equal(badOrigin.statusCode, 403);

    const badHost = await rawHttpPost(
      daemon.url,
      { jsonrpc: "2.0", id: 3, method: "wallet_connect", params: {} },
      {
        [AUTH_HEADER_NAME]: daemon.authToken,
        Host: "rebind.attacker.example:8788"
      }
    );
    assert.equal(badHost.statusCode, 403);
  });

  it("isolates COLD tier from dApp signing, enforces sticky balance floor, and rate-limits unlock", async () => {
    const headers = { [AUTH_HEADER_NAME]: daemon.authToken };

    const created = await rawHttpPost(
      daemon.url,
      {
        jsonrpc: "2.0",
        id: 10,
        method: "wallet_createVault",
        params: { passphrase: "StrongVaultPass#2026!" }
      },
      headers
    );
    assert.equal(created.statusCode, 200);
    assert.equal(created.json.result.status, "VAULT_CREATED_AND_UNLOCKED");
    const summary = created.json.result.summary;
    const hotPubkey = summary.primaryHotWallet.pubkey;
    const bh = randomPubkeyB58();

    const cleanTx = compileV0MessageFast(hotPubkey, bh, [
      buildSolTransferIx(hotPubkey, randomPubkeyB58(), 100_000_000n)
    ]);

    // COLD tier must NEVER sign dApp transactions or off-chain messages
    const coldSignAttempt = await rawHttpPost(
      daemon.url,
      {
        jsonrpc: "2.0",
        id: 11,
        method: "wallet_signTransaction",
        params: {
          tier: "COLD",
          transactionBase64: cleanTx.toString("base64")
        }
      },
      headers
    );
    assert.ok(coldSignAttempt.json.error.message.includes("COLD_VAULT_DAPP_SIGNING_FORBIDDEN"));

    // HOT tier signs clean transaction and records sticky balance floor
    const hotSignOk = await rawHttpPost(
      daemon.url,
      {
        jsonrpc: "2.0",
        id: 12,
        method: "wallet_signTransaction",
        params: {
          tier: "HOT",
          transactionBase64: cleanTx.toString("base64"),
          currentWalletBalanceLamports: "10000000000",
          maxApprovedSolLamports: "500000000"
        }
      },
      headers
    );
    assert.equal(hotSignOk.json.result.approved, true);

    // Attempting to under-report wallet balance on subsequent call without passphrase must fail
    const underreportAttempt = await rawHttpPost(
      daemon.url,
      {
        jsonrpc: "2.0",
        id: 13,
        method: "wallet_signTransaction",
        params: {
          tier: "HOT",
          transactionBase64: cleanTx.toString("base64"),
          currentWalletBalanceLamports: "1000000000",
          maxApprovedSolLamports: "500000000"
        }
      },
      headers
    );
    assert.equal(underreportAttempt.json.result.approved, false);
    assert.equal(
      underreportAttempt.json.result.ruleTriggered,
      "RULE_10_BALANCE_FLOOR_UNDERREPORT_BLOCKED"
    );

    // COLD vault OTS rotation to own HOT wallet works and advances activeColdIndex to 1
    const rotateRes = await rawHttpPost(
      daemon.url,
      {
        jsonrpc: "2.0",
        id: 14,
        method: "qsafe_rotateColdVault",
        params: {
          destinationPubkey: hotPubkey,
          spendLamports: "1000000000",
          currentColdBalanceLamports: "5000000000"
        }
      },
      headers
    );
    assert.equal(rotateRes.json.result.status, "COLD_VAULT_OTS_ROTATED_AND_SIGNED");
    assert.equal(rotateRes.json.result.newQuantumColdVaultIndex, 1);

    // Brute-force PBKDF2 unlock lockout after 3 wrong attempts
    const savedEnvelope = JSON.parse(JSON.stringify(daemon.bridge.vault.envelope));
    for (let i = 1; i <= 3; i++) {
      const bad = await rawHttpPost(
        daemon.url,
        {
          jsonrpc: "2.0",
          id: 20 + i,
          method: "wallet_unlockVault",
          params: { envelope: savedEnvelope, passphrase: `WrongPassphrase#${i}` }
        },
        headers
      );
      assert.ok(bad.json.error);
    }

    const lockedOut = await rawHttpPost(
      daemon.url,
      {
        jsonrpc: "2.0",
        id: 24,
        method: "wallet_unlockVault",
        params: { envelope: savedEnvelope, passphrase: "StrongVaultPass#2026!" }
      },
      headers
    );
    assert.ok(lockedOut.json.error.message.includes("VAULT_UNLOCK_RATE_LIMITED"));
  });
});
