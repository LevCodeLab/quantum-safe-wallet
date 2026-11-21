"use strict";

/**
 * quantum-safe-wallet - Part 3: Clean Solana V0 Transaction Compiler & Guarded Signer
 * ===================================================================================
 * Zero-dependency Solana V0 (0x80) binary message compiler, ComputeBudget / SOL / SPL
 * transfer builders, and firewall-guarded dual-signature (Ed25519 + WOTS+/XMSS) pipeline.
 */

const { encodeB58, decodeB58, signEd25519Seed32Native } = require("./vault_crypto");
const {
  BytecodeDrainerFirewall,
  SYSTEM_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID
} = require("./drainer_firewall");

const SOLANA_PACKET_MTU_BYTES = 1232;
const VALID_SIGNING_TIERS = new Set(["HOT", "BURNER", "COLD"]);

function encodeCompactU16(val) {
  if (val < 0x80) {
    return Buffer.from([val]);
  }
  if (val < 0x4000) {
    return Buffer.from([(val & 0x7f) | 0x80, (val >> 7) & 0x7f]);
  }
  return Buffer.from([
    (val & 0x7f) | 0x80,
    ((val >> 7) & 0x7f) | 0x80,
    (val >> 14) & 0x03
  ]);
}

/**
 * Compiles a Solana V0 (0x80) TransactionMessage with optional Address Lookup Table (ALT) compression.
 */
function compileV0MessageFast(payerB58, blockhashB58, instructions, altTables = []) {
  const metaMap = new Map();
  const programSet = new Set();

  metaMap.set(payerB58, { b58: payerB58, isSigner: true, isWritable: true });

  for (let i = 0; i < instructions.length; i++) {
    const ix = instructions[i];
    programSet.add(ix.programId);
    if (!metaMap.has(ix.programId)) {
      metaMap.set(ix.programId, { b58: ix.programId, isSigner: false, isWritable: false });
    }
    for (let j = 0; j < ix.keys.length; j++) {
      const k = ix.keys[j];
      const existing = metaMap.get(k.pubkey);
      if (!existing) {
        metaMap.set(k.pubkey, {
          b58: k.pubkey,
          isSigner: Boolean(k.isSigner),
          isWritable: Boolean(k.isWritable)
        });
      } else {
        if (k.isSigner) existing.isSigner = true;
        if (k.isWritable) existing.isWritable = true;
      }
    }
  }

  const altLookupIndex = new Map();
  for (let t = 0; t < altTables.length; t++) {
    const addrs = altTables[t].addressesB58 || [];
    for (let a = 0; a < addrs.length && a < 256; a++) {
      if (!altLookupIndex.has(addrs[a])) {
        altLookupIndex.set(addrs[a], { tableIdx: t, addrIdx: a });
      }
    }
  }

  const writableSignedOthers = [];
  const readonlySigned = [];
  const writableUnsigned = [];
  const readonlyUnsigned = [];
  const tableBuckets = altTables.map((t) => ({
    tableKeyB58: t.tableKeyB58,
    writable: [],
    readonly: []
  }));

  for (const [b58, m] of metaMap.entries()) {
    if (b58 === payerB58) continue;
    if (m.isSigner) {
      if (m.isWritable) writableSignedOthers.push(m);
      else readonlySigned.push(m);
      continue;
    }
    if (altTables.length > 0 && !programSet.has(b58)) {
      const loc = altLookupIndex.get(b58);
      if (loc !== undefined) {
        if (m.isWritable) tableBuckets[loc.tableIdx].writable.push({ b58, addrIdx: loc.addrIdx });
        else tableBuckets[loc.tableIdx].readonly.push({ b58, addrIdx: loc.addrIdx });
        continue;
      }
    }
    if (m.isWritable) writableUnsigned.push(m);
    else readonlyUnsigned.push(m);
  }

  const activeTables = tableBuckets.filter(
    (t) => t.writable.length > 0 || t.readonly.length > 0
  );

  const staticAccounts = [
    metaMap.get(payerB58),
    ...writableSignedOthers,
    ...readonlySigned,
    ...writableUnsigned,
    ...readonlyUnsigned
  ];

  const numRequiredSignatures = 1 + writableSignedOthers.length + readonlySigned.length;
  const numReadonlySigned = readonlySigned.length;
  const numReadonlyUnsigned = readonlyUnsigned.length;

  const idxMap = new Map();
  let cursorIdx = 0;
  for (const acc of staticAccounts) {
    idxMap.set(acc.b58, cursorIdx++);
  }
  for (const tbl of activeTables) {
    for (const w of tbl.writable) idxMap.set(w.b58, cursorIdx++);
  }
  for (const tbl of activeTables) {
    for (const r of tbl.readonly) idxMap.set(r.b58, cursorIdx++);
  }

  const chunks = [];
  chunks.push(
    Buffer.from([
      0x80,
      numRequiredSignatures,
      numReadonlySigned,
      numReadonlyUnsigned
    ])
  );
  chunks.push(encodeCompactU16(staticAccounts.length));

  for (const acc of staticAccounts) {
    chunks.push(decodeB58(acc.b58));
  }
  chunks.push(decodeB58(blockhashB58));

  chunks.push(encodeCompactU16(instructions.length));
  for (const ix of instructions) {
    chunks.push(Buffer.from([idxMap.get(ix.programId)]));
    chunks.push(encodeCompactU16(ix.keys.length));
    chunks.push(Buffer.from(ix.keys.map((k) => idxMap.get(k.pubkey))));
    chunks.push(encodeCompactU16(ix.data.length));
    chunks.push(Buffer.from(ix.data));
  }

  chunks.push(encodeCompactU16(activeTables.length));
  for (const tbl of activeTables) {
    chunks.push(decodeB58(tbl.tableKeyB58));
    chunks.push(encodeCompactU16(tbl.writable.length));
    chunks.push(Buffer.from(tbl.writable.map((w) => w.addrIdx)));
    chunks.push(encodeCompactU16(tbl.readonly.length));
    chunks.push(Buffer.from(tbl.readonly.length > 0 ? tbl.readonly.map((r) => r.addrIdx) : []));
  }

  return Buffer.concat(chunks);
}

function buildSetComputeUnitLimitIx(units) {
  const data = Buffer.allocUnsafe(5);
  data[0] = 2;
  data.writeUInt32LE(units >>> 0, 1);
  return {
    programId: COMPUTE_BUDGET_PROGRAM_ID,
    keys: [],
    data
  };
}

function buildSetComputeUnitPriceIx(microLamports) {
  const data = Buffer.allocUnsafe(9);
  data[0] = 3;
  data.writeBigUInt64LE(BigInt(microLamports), 1);
  return {
    programId: COMPUTE_BUDGET_PROGRAM_ID,
    keys: [],
    data
  };
}

function buildSolTransferIx(fromPubkeyB58, toPubkeyB58, lamports) {
  const data = Buffer.allocUnsafe(12);
  data.writeUInt32LE(2, 0);
  data.writeBigUInt64LE(BigInt(lamports), 4);
  return {
    programId: SYSTEM_PROGRAM_ID,
    keys: [
      { pubkey: fromPubkeyB58, isSigner: true, isWritable: true },
      { pubkey: toPubkeyB58, isSigner: false, isWritable: true }
    ],
    data
  };
}

function buildSplTransferCheckedIx({
  sourceAtaB58,
  mintB58,
  destinationAtaB58,
  ownerPubkeyB58,
  amount,
  decimals,
  isToken2022 = false
}) {
  const data = Buffer.allocUnsafe(10);
  data[0] = 12; // TransferChecked = 12
  data.writeBigUInt64LE(BigInt(amount), 1);
  data[9] = decimals & 0xff;
  return {
    programId: isToken2022 ? TOKEN_2022_PROGRAM_ID : SPL_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: sourceAtaB58, isSigner: false, isWritable: true },
      { pubkey: mintB58, isSigner: false, isWritable: false },
      { pubkey: destinationAtaB58, isSigner: false, isWritable: true },
      { pubkey: ownerPubkeyB58, isSigner: true, isWritable: false }
    ],
    data
  };
}

function buildCloseTokenAccountIx(
  ataPubkeyB58,
  destinationPubkeyB58,
  ownerPubkeyB58,
  isToken2022 = false
) {
  return {
    programId: isToken2022 ? TOKEN_2022_PROGRAM_ID : SPL_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: ataPubkeyB58, isSigner: false, isWritable: true },
      { pubkey: destinationPubkeyB58, isSigner: false, isWritable: true },
      { pubkey: ownerPubkeyB58, isSigner: true, isWritable: false }
    ],
    data: Buffer.from([9])
  };
}

/**
 * Inspects `rawTxBytes` through `BytecodeDrainerFirewall`, optionally attaches an
 * on-chain SVM balance-floor guard when calling unverified external programs, and
 * dual-signs the resulting message with Ed25519 + stateful WOTS+/XMSS.
 */
function guardAndSignTransaction(vault, rawTxBytes, opts = {}) {
  const t0 = process.hrtime.bigint();
  const tier = opts.tier || "HOT";
  if (!VALID_SIGNING_TIERS.has(tier)) {
    throw new Error(`INVALID_TIER: unsupported signing tier ${JSON.stringify(tier)}`);
  }

  const summary = vault.getPublicVaultSummary();
  if (tier === "BURNER" && opts.burnerIndex !== undefined && opts.burnerIndex !== null) {
    const burners = summary.burnerPool.burners || [];
    if (
      !Number.isInteger(opts.burnerIndex) ||
      opts.burnerIndex < 0 ||
      opts.burnerIndex >= burners.length
    ) {
      throw new Error(`INVALID_BURNER_INDEX: ${String(opts.burnerIndex)} is outside burner pool`);
    }
  }

  const userPubkeyB58 =
    tier === "COLD"
      ? summary.quantumColdVault.pubkey
      : tier === "BURNER"
      ? summary.burnerPool.burners[opts.burnerIndex ?? summary.burnerPool.activeBurnerIndex]?.pubkey
      : summary.primaryHotWallet.pubkey;

  const altTables = opts.altTables || [];
  const altLookupMap = new Map();
  for (const tbl of altTables) {
    if (tbl && tbl.tableKeyB58 && Array.isArray(tbl.addressesB58)) {
      altLookupMap.set(tbl.tableKeyB58, tbl.addressesB58);
    }
  }
  if (opts.altLookupMap instanceof Map) {
    for (const [k, v] of opts.altLookupMap.entries()) {
      altLookupMap.set(k, v);
    }
  }

  const trustedAddresses = [
    summary.quantumColdVault.pubkey,
    summary.quantumColdVault.hashLockedQuantumPdaVault,
    summary.primaryHotWallet.pubkey,
    ...(summary.burnerPool.burners || []).map((b) => b.pubkey),
    ...(opts.trustedAddresses || [])
  ].filter(Boolean);

  const firewallAudit = BytecodeDrainerFirewall.inspectTransactionBytes(rawTxBytes, {
    userPubkeyB58,
    userTokenAtas: opts.userTokenAtas,
    requireTokenInventory: Boolean(opts.requireTokenInventory),
    maxPriorityFeeLamports: opts.maxPriorityFeeLamports,
    protectedTokenAtas: opts.protectedTokenAtas || [],
    trustedAddresses,
    allowedTokenTransferDestinations: opts.allowedTokenTransferDestinations || [],
    allowDirectTokenTransfers: Boolean(opts.allowDirectTokenTransfers),
    allowTokenBurn: Boolean(opts.allowTokenBurn),
    maxApprovedSolLamports: opts.maxApprovedSolLamports ?? 2_000_000_000n,
    allowExternalDappWithGuard: opts.allowExternalDappWithGuard ?? true,
    altLookupMap
  });

  if (!firewallAudit.safe) {
    return {
      status: "BLOCKED_BY_DRAINER_FIREWALL",
      firewallAudit,
      totalLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
    };
  }

  const decoded = firewallAudit.decoded;
  const slot = opts.slot ?? 0;

  // Preserve co-signatures on multi-signer canonical transactions; block multi-signer unverified CPIs
  if (decoded.header.numRequiredSignatures > 1 && !opts.forceRecompileMultiSigner) {
    if (firewallAudit.requiresOnChainBalanceFloorGuard) {
      const reason =
        "Blocked multi-signer transaction invoking an unverified external program: co-signatures prevent injecting the mandatory On-Chain Balance-Floor Guard.";
      return {
        status: "BLOCKED_BY_DRAINER_FIREWALL",
        onChainBalanceFloorGuardAttached: false,
        balanceFloorInvariant: null,
        firewallAudit: {
          ...firewallAudit,
          safe: false,
          tier: "BLOCKED_DRAINER_ATTACK",
          ruleTriggered: "RULE_03C_MULTI_SIGNER_UNVERIFIED_CPI_BLOCKED",
          reason,
          threats: [{ rule: "RULE_03C_MULTI_SIGNER_UNVERIFIED_CPI_BLOCKED", severity: "CRITICAL", detail: reason }]
        },
        totalLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
      };
    }

    const numSigs = decoded.header.numRequiredSignatures;
    const userSignerIdx = decoded.staticAccounts.findIndex(
      (a) => a.isSigner && a.pubkeyB58 === userPubkeyB58
    );
    if (userSignerIdx < 0 || userSignerIdx >= numSigs) {
      throw new Error(`Multi-signer transaction does not list ${userPubkeyB58} as a required signer`);
    }

    const userSig64 = vault._withTierSeed32(tier, opts.burnerIndex, (seed32) =>
      signEd25519Seed32Native(seed32, decoded.messageBytes)
    );
    const sigSlots = new Array(numSigs);
    for (let s = 0; s < numSigs; s++) {
      if (s === userSignerIdx) {
        sigSlots[s] = userSig64;
      } else if (decoded.signatures[s] && decoded.signatures[s].length === 64) {
        sigSlots[s] = Buffer.from(decoded.signatures[s]);
      } else {
        sigSlots[s] = Buffer.alloc(64, 0);
      }
    }

    const wireTx = Buffer.concat([
      encodeCompactU16(numSigs),
      ...sigSlots,
      decoded.messageBytes
    ]);
    const quantumProof = vault.signQuantumProof(slot, decoded.messageBytes);

    return {
      status: "GUARDED_AND_SIGNED",
      multiSignerPreserved: true,
      numRequiredSignatures: numSigs,
      firewallTier: firewallAudit.tier,
      signerPubkey: userPubkeyB58,
      signatureBase58: encodeB58(userSig64),
      wireTransaction: wireTx,
      wireBytes: wireTx.length,
      onChainBalanceFloorGuardAttached: false,
      roundTripGuardActive: false,
      balanceFloorInvariant: null,
      directSolOutLamports: firewallAudit.totalDirectSolOutLamports || 0n,
      quantumProof,
      totalLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
    };
  }

  // If canonical safe transaction needs no modification and no override blockhash, sign directly or recompile
  const coreInstructions = [];
  let hasComputeLimit = false;
  let hasComputePrice = false;

  for (const ix of decoded.instructions) {
    if (ix.programIdB58 === COMPUTE_BUDGET_PROGRAM_ID && ix.data.length > 0) {
      if (ix.data[0] === 2) hasComputeLimit = true;
      if (ix.data[0] === 3) hasComputePrice = true;
    }
    coreInstructions.push({
      programId: ix.programIdB58,
      keys: ix.accounts.map((a) => ({
        pubkey: a.pubkeyB58,
        isSigner: a.isSigner,
        isWritable: a.isWritable
      })),
      data: ix.data
    });
  }

  const finalInstructions = [];
  if (!hasComputeLimit && opts.computeUnitLimit) {
    finalInstructions.push(buildSetComputeUnitLimitIx(opts.computeUnitLimit));
  }
  if (!hasComputePrice && opts.computeUnitPriceMicroLamports) {
    finalInstructions.push(buildSetComputeUnitPriceIx(opts.computeUnitPriceMicroLamports));
  }
  finalInstructions.push(...coreInstructions);

  let balanceFloorGuard = null;
  const useRoundTripGuard =
    firewallAudit.requiresOnChainBalanceFloorGuard &&
    tier === "HOT" &&
    opts.useRoundTripDualSignerGuard !== false;

  if (firewallAudit.requiresOnChainBalanceFloorGuard) {
    if (
      opts.currentWalletBalanceLamports === undefined ||
      opts.currentWalletBalanceLamports === null
    ) {
      throw new Error(
        "EXPLICIT_VERIFIED_BALANCE_REQUIRED: External unverified dApp requires explicit currentWalletBalanceLamports for On-Chain Balance-Floor Guard"
      );
    }

    const guardAnchorPubkey = useRoundTripGuard
      ? summary.primaryHotWallet.balanceFloorGuardAnchorPubkey
      : summary.quantumColdVault.pubkey;

    try {
      balanceFloorGuard = BytecodeDrainerFirewall.buildOnChainBalanceFloorGuard({
        userHotWalletB58: userPubkeyB58,
        userSafeVaultB58: guardAnchorPubkey,
        currentBalanceLamports: opts.currentWalletBalanceLamports,
        maxApprovedSpendLamports: opts.maxApprovedSolLamports ?? 2_000_000_000n,
        protectedTokenAtas: opts.protectedTokenAtas || []
      });
    } catch (guardErr) {
      return {
        status: "BLOCKED_BY_DRAINER_FIREWALL",
        onChainBalanceFloorGuardAttached: false,
        balanceFloorInvariant: "BLOCKED_INSUFFICIENT_PROTECTED_FLOOR (< 0.01 SOL)",
        firewallAudit: {
          ...firewallAudit,
          safe: false,
          tier: "BLOCKED_DRAINER_ATTACK",
          ruleTriggered: "RULE_10_BALANCE_FLOOR_COLLAPSE_BLOCKED",
          reason: guardErr.message,
          threats: [
            {
              rule: "RULE_10_BALANCE_FLOOR_COLLAPSE_BLOCKED",
              severity: "CRITICAL",
              detail: guardErr.message
            }
          ]
        },
        totalLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
      };
    }

    if (useRoundTripGuard) {
      finalInstructions.push(...balanceFloorGuard.roundTripDualSignerGuardIxs);
    } else {
      finalInstructions.push(
        balanceFloorGuard.singleSignerGuardIx,
        ...(balanceFloorGuard.tokenFloorGuardIxs || []),
        ...(balanceFloorGuard.tokenDelegateRevokeIxs || [])
      );
    }
  }

  const blockhashB58 = opts.overrideBlockhashB58 || decoded.recentBlockhashB58;
  const compiledMessageBytes = compileV0MessageFast(
    userPubkeyB58,
    blockhashB58,
    finalInstructions,
    altTables
  );

  const dualSigned = useRoundTripGuard
    ? vault.dualSignRoundTripGuardedMessage(compiledMessageBytes, {
        primaryTier: "HOT",
        primaryIndex: 0,
        guardTier: "GUARD_ANCHOR",
        guardIndex: 0,
        slot
      })
    : vault.dualSignTransactionBytes(compiledMessageBytes, {
        tier,
        index: opts.burnerIndex,
        slot
      });

  if (dualSigned.wireBytes > SOLANA_PACKET_MTU_BYTES) {
    throw new Error(
      `Compiled transaction (${dualSigned.wireBytes}B) exceeds Solana packet MTU (${SOLANA_PACKET_MTU_BYTES}B)`
    );
  }

  return {
    status: "GUARDED_AND_SIGNED",
    firewallTier: firewallAudit.tier,
    signerPubkey: dualSigned.signerPubkey,
    signatureBase58: dualSigned.signatureBase58,
    wireTransaction: dualSigned.wireTransaction,
    wireBytes: dualSigned.wireBytes,
    onChainBalanceFloorGuardAttached: Boolean(balanceFloorGuard),
    roundTripGuardActive: useRoundTripGuard,
    balanceFloorInvariant: balanceFloorGuard ? balanceFloorGuard.svmInvariant : null,
    directSolOutLamports: firewallAudit.totalDirectSolOutLamports || 0n,
    quantumProof: dualSigned.quantumProof,
    totalLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
  };
}

module.exports = {
  SOLANA_PACKET_MTU_BYTES,
  encodeCompactU16,
  compileV0MessageFast,
  buildSetComputeUnitLimitIx,
  buildSetComputeUnitPriceIx,
  buildSolTransferIx,
  buildSplTransferCheckedIx,
  buildCloseTokenAccountIx,
  guardAndSignTransaction
};
