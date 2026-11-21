"use strict";

/**
 * quantum-safe-wallet - Part 2: Static Binary Solana Transaction Firewall
 * =======================================================================
 * Sub-150us static binary Solana wire decoder (Legacy and V0 = 0x80) and
 * 10-rule anti-drainer transaction firewall with native on-chain SVM
 * balance-floor guard injection.
 *
 * Rules:
 * - RULE_01: SystemProgram::Assign / AssignWithSeed / unverified CreateAccount hijack
 * - RULE_02: SPL-Token & Token-2022 SetAuthority (AccountOwner / CloseAuthority) theft
 *            plus unauthorized direct Transfer / Burn / unverified extension opcodes
 * - RULE_03: Unknown writable-wallet CPI quarantine & unresolved V0 ALT fail-closed
 * - RULE_04: SystemProgram::AdvanceNonceAccount offline durable-nonce time-bombs
 * - RULE_05: signMessage() raw TransactionMessage (Legacy / V0) bit-flip phishing
 * - RULE_06: Unlimited SPL Approve / ApproveChecked delegation + 1-byte Revoke builder
 * - RULE_07: Malicious Token-2022 TLV extensions (PermanentDelegate, TransferHook, 50%+ fee)
 * - RULE_08: CloseAccount rent redirection, fake WSOL owner init, SOL & priority-fee caps
 * - RULE_09: Vanity address poisoning & homoglyph lookalike detector
 * - RULE_10: On-chain SVM balance-floor guard + self-transfer token floor + auto-Revoke
 */

const { encodeB58, decodeB58 } = require("./vault_crypto");

// Canonical Solana Program IDs ONLY
const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";
const COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111";
const SPL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATA_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const MEMO_V1_PROGRAM_ID = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";

const CANONICAL_SOLANA_PROGRAMS = new Set([
  SYSTEM_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  ATA_PROGRAM_ID,
  MEMO_PROGRAM_ID,
  MEMO_V1_PROGRAM_ID
]);

function readCompactU16(buf, offset) {
  let val = 0;
  let shift = 0;
  let cursor = offset;
  for (let i = 0; i < 3; i++) {
    if (cursor >= buf.length) {
      throw new Error("Truncated compact-u16 in transaction buffer");
    }
    const byte = buf[cursor++];
    val |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value: val, nextOffset: cursor };
    }
    shift += 7;
  }
  throw new Error("Malformed compact-u16 (>3 bytes)");
}

/**
 * Decodes either a full Solana wire transaction ([sigCount] + [64B * N] + [messageBytes])
 * or raw TransactionMessage bytes (Legacy or V0 = 0x80) in <100us.
 */
function decodeWireTransactionFast(rawBytes, opts = {}) {
  const buf = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(rawBytes);
  if (buf.length < 40) {
    throw new Error(`Transaction buffer too short (${buf.length} bytes)`);
  }

  let offset = 0;
  const signatures = [];
  let messageStartOffset = 0;

  if (!opts.isMessageOnly) {
    const firstByte = buf[0];
    const looksLikeRawVersionedMessage = firstByte === 0x80;
    if (!looksLikeRawVersionedMessage && firstByte >= 1 && firstByte <= 16) {
      const potentialMsgOffset = 1 + firstByte * 64;
      if (potentialMsgOffset + 36 <= buf.length) {
        const msgFirstByte = buf[potentialMsgOffset];
        const isValidNextHeader =
          msgFirstByte === 0x80 ||
          (msgFirstByte >= 1 && msgFirstByte <= 16 && buf[potentialMsgOffset + 3] >= 1);
        if (isValidNextHeader) {
          for (let s = 0; s < firstByte; s++) {
            const sigStart = 1 + s * 64;
            signatures.push(buf.subarray(sigStart, sigStart + 64));
          }
          offset = potentialMsgOffset;
          messageStartOffset = potentialMsgOffset;
        }
      }
    }
  }

  let version = "legacy";
  const prefixByte = buf[offset];
  if ((prefixByte & 0x80) !== 0) {
    version = prefixByte & 0x7f;
    if (version !== 0) {
      throw new Error(`Unsupported versioned transaction version: ${version}`);
    }
    offset += 1;
  }

  const numRequiredSignatures = buf[offset++];
  const numReadonlySignedAccounts = buf[offset++];
  const numReadonlyUnsignedAccounts = buf[offset++];

  if (numRequiredSignatures < 1 || numRequiredSignatures > 32) {
    throw new Error(`Invalid numRequiredSignatures: ${numRequiredSignatures}`);
  }

  const keyCountRes = readCompactU16(buf, offset);
  const numStaticKeys = keyCountRes.value;
  offset = keyCountRes.nextOffset;

  if (numStaticKeys < numRequiredSignatures || offset + numStaticKeys * 32 + 32 > buf.length) {
    throw new Error("Truncated static account keys or blockhash");
  }

  const numWritableSigned = numRequiredSignatures - numReadonlySignedAccounts;
  const numUnsigned = numStaticKeys - numRequiredSignatures;
  const numWritableUnsigned = numUnsigned - numReadonlyUnsignedAccounts;

  const staticAccounts = new Array(numStaticKeys);
  for (let i = 0; i < numStaticKeys; i++) {
    const pkBuf = Buffer.from(buf.subarray(offset, offset + 32));
    offset += 32;
    const isSigner = i < numRequiredSignatures;
    const isWritable = isSigner
      ? i < numWritableSigned
      : i - numRequiredSignatures < numWritableUnsigned;
    staticAccounts[i] = {
      index: i,
      pubkeyBuf: pkBuf,
      pubkeyB58: encodeB58(pkBuf),
      isSigner,
      isWritable,
      isAltLoaded: false
    };
  }

  const recentBlockhashBuf = Buffer.from(buf.subarray(offset, offset + 32));
  const recentBlockhashB58 = encodeB58(recentBlockhashBuf);
  offset += 32;

  const ixCountRes = readCompactU16(buf, offset);
  const numInstructions = ixCountRes.value;
  offset = ixCountRes.nextOffset;

  const rawInstructions = new Array(numInstructions);
  for (let i = 0; i < numInstructions; i++) {
    if (offset >= buf.length) throw new Error(`Truncated instruction #${i}`);
    const programIdIndex = buf[offset++];

    const accRes = readCompactU16(buf, offset);
    const numAccs = accRes.value;
    offset = accRes.nextOffset;
    if (offset + numAccs > buf.length) throw new Error(`Truncated accounts in instruction #${i}`);
    const accountIndices = Array.from(buf.subarray(offset, offset + numAccs));
    offset += numAccs;

    const dataRes = readCompactU16(buf, offset);
    const dataLen = dataRes.value;
    offset = dataRes.nextOffset;
    if (offset + dataLen > buf.length) throw new Error(`Truncated data in instruction #${i}`);
    const data = Buffer.from(buf.subarray(offset, offset + dataLen));
    offset += dataLen;

    rawInstructions[i] = {
      ixIndex: i,
      programIdIndex,
      accountIndices,
      data
    };
  }

  const addressTableLookups = [];
  const loadedWritableAccounts = [];
  const loadedReadonlyAccounts = [];

  if (version !== "legacy" && offset < buf.length) {
    const altCountRes = readCompactU16(buf, offset);
    const numAltLookups = altCountRes.value;
    offset = altCountRes.nextOffset;

    for (let t = 0; t < numAltLookups; t++) {
      if (offset + 32 > buf.length) throw new Error("Truncated ALT table key");
      const tableKeyBuf = Buffer.from(buf.subarray(offset, offset + 32));
      const tableKeyB58 = encodeB58(tableKeyBuf);
      offset += 32;

      const wRes = readCompactU16(buf, offset);
      offset = wRes.nextOffset;
      if (offset + wRes.value > buf.length) throw new Error("Truncated ALT writable indexes");
      const writableIndexes = Array.from(buf.subarray(offset, offset + wRes.value));
      offset += wRes.value;

      const rRes = readCompactU16(buf, offset);
      offset = rRes.nextOffset;
      if (offset + rRes.value > buf.length) throw new Error("Truncated ALT readonly indexes");
      const readonlyIndexes = Array.from(buf.subarray(offset, offset + rRes.value));
      offset += rRes.value;

      addressTableLookups.push({
        tableKeyB58,
        tableKeyBuf,
        writableIndexes,
        readonlyIndexes
      });

      const knownTableAddrs = opts.altLookupMap && opts.altLookupMap.get(tableKeyB58);

      for (const wIdx of writableIndexes) {
        const resolvedB58 =
          knownTableAddrs && knownTableAddrs[wIdx]
            ? knownTableAddrs[wIdx]
            : `ALT_WRITABLE_${tableKeyB58.slice(0, 6)}_${wIdx}`;
        loadedWritableAccounts.push({
          index: staticAccounts.length + loadedWritableAccounts.length,
          pubkeyBuf: null,
          pubkeyB58: resolvedB58,
          isSigner: false,
          isWritable: true,
          isAltLoaded: true
        });
      }
      for (const rIdx of readonlyIndexes) {
        const resolvedB58 =
          knownTableAddrs && knownTableAddrs[rIdx]
            ? knownTableAddrs[rIdx]
            : `ALT_READONLY_${tableKeyB58.slice(0, 6)}_${rIdx}`;
        loadedReadonlyAccounts.push({
          index:
            staticAccounts.length +
            loadedWritableAccounts.length +
            loadedReadonlyAccounts.length,
          pubkeyBuf: null,
          pubkeyB58: resolvedB58,
          isSigner: false,
          isWritable: false,
          isAltLoaded: true
        });
      }
    }
  }

  const allAccounts = [
    ...staticAccounts,
    ...loadedWritableAccounts,
    ...loadedReadonlyAccounts
  ];

  const instructions = rawInstructions.map((rawIx) => {
    const progMeta = allAccounts[rawIx.programIdIndex];
    const programIdB58 = progMeta ? progMeta.pubkeyB58 : "UNKNOWN_PROGRAM_INDEX";
    const accounts = rawIx.accountIndices.map(
      (idx) =>
        allAccounts[idx] || {
          index: idx,
          pubkeyB58: `UNRESOLVED_IDX_${idx}`,
          isSigner: false,
          isWritable: false,
          isAltLoaded: true
        }
    );
    return {
      ixIndex: rawIx.ixIndex,
      programIdIndex: rawIx.programIdIndex,
      programIdB58,
      accountIndices: rawIx.accountIndices,
      accounts,
      data: rawIx.data
    };
  });

  return {
    version,
    header: {
      numRequiredSignatures,
      numReadonlySignedAccounts,
      numReadonlyUnsignedAccounts
    },
    signatures,
    messageBytes: Buffer.from(buf.subarray(messageStartOffset)),
    staticAccounts,
    allAccounts,
    feePayerB58: staticAccounts[0] ? staticAccounts[0].pubkeyB58 : null,
    recentBlockhashB58,
    recentBlockhashBuf,
    instructions,
    addressTableLookups
  };
}

class BytecodeDrainerFirewall {
  static inspectTransactionBytes(rawTxBytes, context = {}) {
    const t0 = process.hrtime.bigint();
    const userPubkeyB58 = context.userPubkeyB58;
    if (!userPubkeyB58) {
      throw new Error("context.userPubkeyB58 is required for drainer firewall audit");
    }

    const userAtas = new Set(context.userTokenAtas || []);
    const allowedTokenDestSet = new Set(context.allowedTokenTransferDestinations || []);
    const protectedAtaSet = new Set(
      (context.protectedTokenAtas || [])
        .map((t) => (typeof t === "string" ? t : t && t.ataPubkeyB58))
        .filter(Boolean)
    );
    const trustedAddressesList = Array.from(
      new Set([userPubkeyB58, ...(context.trustedAddresses || [])])
    );
    const maxApprovedLamports = BigInt(context.maxApprovedSolLamports ?? 5_000_000_000n);

    let decoded;
    try {
      decoded = decodeWireTransactionFast(rawTxBytes, {
        altLookupMap: context.altLookupMap
      });
    } catch (err) {
      return {
        safe: false,
        tier: "BLOCKED_DRAINER_ATTACK",
        ruleTriggered: "RULE_00_MALFORMED_WIRE_PAYLOAD",
        reason: `Malformed transaction wire payload: ${err.message}`,
        threats: [{ rule: "RULE_00", severity: "CRITICAL", detail: err.message }],
        inspectLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
      };
    }

    const threats = [];
    const warnings = [];
    let totalDirectSolOutLamports = 0n;
    let invokesUnverifiedProgram = false;

    // Fail closed if any V0 Address Lookup Table (ALT) account or program index is unresolved
    const hasUnresolvedAlt =
      decoded.allAccounts.some((a) => a.isAltLoaded && a.pubkeyB58.startsWith("ALT_")) ||
      decoded.instructions.some(
        (ix) =>
          ix.programIdB58 === "UNKNOWN_PROGRAM_INDEX" ||
          ix.programIdB58.startsWith("ALT_") ||
          ix.accounts.some(
            (a) =>
              a.pubkeyB58.startsWith("ALT_") || a.pubkeyB58.startsWith("UNRESOLVED_IDX_")
          )
      );
    if (hasUnresolvedAlt) {
      threats.push({
        rule: "RULE_03B_UNRESOLVED_ALT_ACCOUNT",
        severity: "CRITICAL",
        detail:
          "Blocked transaction containing unresolved Address Lookup Table (ALT) accounts. Resolve all ALT tables prior to signing."
      });
    }

    // Priority-fee burn guard when user is fee payer
    {
      let cuPriceMicro = 0n;
      let cuLimit = null;
      let additionalFeeLamports = 0n;
      let nonBuiltinIxCount = 0;
      for (const cix of decoded.instructions) {
        if (cix.programIdB58 === COMPUTE_BUDGET_PROGRAM_ID) {
          const d = cix.data;
          if (d[0] === 3 && d.length >= 9) cuPriceMicro = d.readBigUInt64LE(1);
          else if (d[0] === 2 && d.length >= 5) cuLimit = BigInt(d.readUInt32LE(1));
          else if (d[0] === 0 && d.length >= 9) {
            cuLimit = BigInt(d.readUInt32LE(1));
            additionalFeeLamports = BigInt(d.readUInt32LE(5));
          }
        } else if (cix.programIdB58 !== SYSTEM_PROGRAM_ID) {
          nonBuiltinIxCount++;
        }
      }
      const defaultLimit = BigInt(Math.max(1, nonBuiltinIxCount)) * 200_000n;
      let effLimit = cuLimit === null ? defaultLimit : cuLimit;
      if (effLimit > 1_400_000n) effLimit = 1_400_000n;
      const priorityFeeLamports =
        (cuPriceMicro * effLimit + 999_999n) / 1_000_000n + additionalFeeLamports;
      const maxPriorityFeeLamports = BigInt(context.maxPriorityFeeLamports ?? 100_000_000n);
      if (decoded.feePayerB58 === userPubkeyB58 && priorityFeeLamports > maxPriorityFeeLamports) {
        threats.push({
          rule: "RULE_08_EXCESSIVE_PRIORITY_FEE",
          severity: "HIGH",
          detail: `Blocked transaction whose implied priority fee is ${Number(priorityFeeLamports) / 1e9} SOL (cap ${Number(maxPriorityFeeLamports) / 1e9} SOL).`
        });
      }
    }

    for (let i = 0; i < decoded.instructions.length; i++) {
      const ix = decoded.instructions[i];
      const prog = ix.programIdB58;
      const data = ix.data;

      // 1. SYSTEM PROGRAM CHECKS (RULE_01, RULE_04, RULE_08, RULE_09)
      if (prog === SYSTEM_PROGRAM_ID && data.length >= 4) {
        const sysDisc = data.readUInt32LE(0);

        if (sysDisc === 4 || sysDisc === 6 || sysDisc === 7) {
          threats.push({
            rule: "RULE_04_NO_EXTERNAL_DURABLE_NONCE",
            severity: "CRITICAL",
            ixIndex: i,
            detail:
              "Blocked Durable Nonce instruction (AdvanceNonceAccount). Durable nonces can be held off-chain and broadcast later."
          });
        }

        if (sysDisc === 5) {
          const touchesUserAsSigner = ix.accounts.some(
            (a) => a.pubkeyB58 === userPubkeyB58 && a.isSigner
          );
          if (touchesUserAsSigner) {
            threats.push({
              rule: "RULE_04B_NONCE_WITHDRAW_BLOCKED",
              severity: "HIGH",
              ixIndex: i,
              detail:
                "Blocked SystemProgram::WithdrawNonceAccount authorized by your wallet."
            });
          }
        }

        if (sysDisc === 1 || sysDisc === 9 || sysDisc === 10) {
          const newOwnerB58 =
            data.length >= 36 ? encodeB58(data.subarray(4, 36)) : "UNKNOWN_OWNER";
          threats.push({
            rule: "RULE_01_NO_SYSTEM_ASSIGN",
            severity: "CRITICAL",
            ixIndex: i,
            detail: `Blocked SystemProgram::Assign ownership transfer attempting to assign wallet ownership to ${newOwnerB58}.`
          });
        }

        if (sysDisc === 0 && data.length >= 52) {
          const lamports = data.readBigUInt64LE(4);
          const fromAcc = ix.accounts[0]?.pubkeyB58;
          const createdAcc = ix.accounts[1]?.pubkeyB58;
          const newOwnerB58 = encodeB58(data.subarray(20, 52));

          if (fromAcc === userPubkeyB58) {
            totalDirectSolOutLamports += lamports;
            if (createdAcc && createdAcc !== userPubkeyB58) {
              const poisonCheck = BytecodeDrainerFirewall.inspectAddressPoisoningRisk(
                createdAcc,
                trustedAddressesList
              );
              if (poisonCheck.poisoningDetected) {
                threats.push({
                  rule: "RULE_09_VANITY_ADDRESS_POISONING",
                  severity: "CRITICAL",
                  ixIndex: i,
                  detail: poisonCheck.reason
                });
              }
            }
          }

          if (!CANONICAL_SOLANA_PROGRAMS.has(newOwnerB58)) {
            threats.push({
              rule: "RULE_01_CREATE_ACCOUNT_UNVERIFIED_OWNER",
              severity: "CRITICAL",
              ixIndex: i,
              detail: `Blocked SystemProgram::CreateAccount assigning account ownership to unverified program ${newOwnerB58}.`
            });
          }
        }

        if (sysDisc === 3 && data.length >= 44) {
          const seedLenBig = data.readBigUInt64LE(36);
          if (seedLenBig > 128n || BigInt(data.length) < 44n + seedLenBig + 48n) {
            threats.push({
              rule: "RULE_01_CREATE_ACCOUNT_WITH_SEED_MALFORMED",
              severity: "CRITICAL",
              ixIndex: i,
              detail: "Blocked malformed SystemProgram::CreateAccountWithSeed payload."
            });
          } else {
            const o = 44 + Number(seedLenBig);
            const lamports = data.readBigUInt64LE(o);
            const newOwnerB58 = encodeB58(data.subarray(o + 16, o + 48));
            const fromAcc = ix.accounts[0]?.pubkeyB58;
            const createdAcc = ix.accounts[1]?.pubkeyB58;
            if (fromAcc === userPubkeyB58) {
              totalDirectSolOutLamports += lamports;
              if (createdAcc && createdAcc !== userPubkeyB58) {
                const poisonCheck = BytecodeDrainerFirewall.inspectAddressPoisoningRisk(
                  createdAcc,
                  trustedAddressesList
                );
                if (poisonCheck.poisoningDetected) {
                  threats.push({
                    rule: "RULE_09_VANITY_ADDRESS_POISONING",
                    severity: "CRITICAL",
                    ixIndex: i,
                    detail: poisonCheck.reason
                  });
                }
              }
            }
            if (!CANONICAL_SOLANA_PROGRAMS.has(newOwnerB58)) {
              threats.push({
                rule: "RULE_01_CREATE_ACCOUNT_UNVERIFIED_OWNER",
                severity: "CRITICAL",
                ixIndex: i,
                detail: `Blocked SystemProgram::CreateAccountWithSeed assigning account ownership to unverified program ${newOwnerB58}.`
              });
            }
          }
        }

        if ((sysDisc === 2 || sysDisc === 11) && data.length >= 12) {
          const lamports = data.readBigUInt64LE(4);
          const fromAcc = ix.accounts[0]?.pubkeyB58;
          const toAcc = ix.accounts[sysDisc === 11 ? 2 : 1]?.pubkeyB58;

          if (fromAcc === userPubkeyB58 || ix.accounts[1]?.pubkeyB58 === userPubkeyB58) {
            totalDirectSolOutLamports += lamports;
            if (toAcc && toAcc !== userPubkeyB58) {
              const poisonCheck = BytecodeDrainerFirewall.inspectAddressPoisoningRisk(
                toAcc,
                trustedAddressesList
              );
              if (poisonCheck.poisoningDetected) {
                threats.push({
                  rule: "RULE_09_VANITY_ADDRESS_POISONING",
                  severity: "CRITICAL",
                  ixIndex: i,
                  detail: poisonCheck.reason
                });
              }
            }
          }
        }
      }

      // 2. SPL-TOKEN & TOKEN-2022 CHECKS (RULE_02, RULE_06, RULE_08, RULE_09)
      if ((prog === SPL_TOKEN_PROGRAM_ID || prog === TOKEN_2022_PROGRAM_ID) && data.length >= 1) {
        const tokDisc = data[0];
        const isTransferCheckedWithFee = tokDisc === 26 && data.length >= 11 && data[1] === 1;

        if (
          (tokDisc === 3 && data.length >= 9) ||
          (tokDisc === 12 && data.length >= 10) ||
          isTransferCheckedWithFee
        ) {
          const amount = isTransferCheckedWithFee
            ? data.readBigUInt64LE(2)
            : data.readBigUInt64LE(1);
          const sourceAta = ix.accounts[0]?.pubkeyB58 || "UNKNOWN_SOURCE_ATA";
          const destAta =
            (tokDisc === 12 || isTransferCheckedWithFee
              ? ix.accounts[2]?.pubkeyB58
              : ix.accounts[1]?.pubkeyB58) || "UNKNOWN_DEST_ATA";
          const authority =
            (tokDisc === 12 || isTransferCheckedWithFee
              ? ix.accounts[3]?.pubkeyB58
              : ix.accounts[2]?.pubkeyB58) || "UNKNOWN_AUTHORITY";

          const isUserSourceOrSigner =
            authority === userPubkeyB58 ||
            userAtas.has(sourceAta) ||
            ix.accounts.some((a) => a.pubkeyB58 === userPubkeyB58 && a.isSigner);

          if (destAta && destAta !== userPubkeyB58 && destAta !== sourceAta) {
            const poisonCheck = BytecodeDrainerFirewall.inspectAddressPoisoningRisk(
              destAta,
              trustedAddressesList
            );
            if (poisonCheck.poisoningDetected) {
              threats.push({
                rule: "RULE_09_VANITY_ADDRESS_POISONING",
                severity: "CRITICAL",
                ixIndex: i,
                detail: poisonCheck.reason
              });
            }
          }

          const isSelfTransferGuard = sourceAta === destAta;
          const isExplicitlyAllowedDest =
            isSelfTransferGuard ||
            destAta === userPubkeyB58 ||
            userAtas.has(destAta) ||
            allowedTokenDestSet.has(destAta) ||
            Boolean(context.allowDirectTokenTransfers);

          if (isUserSourceOrSigner && !isExplicitlyAllowedDest) {
            threats.push({
              rule: "RULE_02B_UNAUTHORIZED_TOKEN_TRANSFER",
              severity: "CRITICAL",
              ixIndex: i,
              detail: `Blocked direct SPL/Token-2022 Transfer (${amount.toString()} units) from ${sourceAta} to unapproved recipient ${destAta}.`
            });
          }
        }

        const AUDITED_SPL_DISCS = new Set([1, 3, 4, 5, 6, 8, 9, 12, 13, 15, 16, 17, 18]);
        if (!AUDITED_SPL_DISCS.has(tokDisc) && !isTransferCheckedWithFee) {
          const touchesUser = ix.accounts.some(
            (a) =>
              a.pubkeyB58 === userPubkeyB58 ||
              a.isSigner ||
              userAtas.has(a.pubkeyB58)
          );
          if (touchesUser) {
            threats.push({
              rule: "RULE_02D_UNVERIFIED_TOKEN_EXTENSION_IX",
              severity: "CRITICAL",
              ixIndex: i,
              detail: `Blocked unverified SPL/Token-2022 extension instruction (discriminator=${tokDisc}) touching user wallet or ATA.`
            });
          }
        }

        if ((tokDisc === 8 && data.length >= 9) || (tokDisc === 15 && data.length >= 10)) {
          const amount = data.readBigUInt64LE(1);
          const sourceAta = ix.accounts[0]?.pubkeyB58 || "UNKNOWN_SOURCE_ATA";
          const authority = ix.accounts[2]?.pubkeyB58 || "UNKNOWN_AUTHORITY";
          const isUserSourceOrSigner =
            authority === userPubkeyB58 ||
            userAtas.has(sourceAta) ||
            ix.accounts.some((a) => a.pubkeyB58 === userPubkeyB58 && a.isSigner);

          if (isUserSourceOrSigner && !context.allowTokenBurn) {
            threats.push({
              rule: "RULE_02C_UNAUTHORIZED_TOKEN_BURN",
              severity: "CRITICAL",
              ixIndex: i,
              detail: `Blocked unauthorized SPL Token Burn (${amount.toString()} units) from token account ${sourceAta}.`
            });
          }
        }

        // RULE_02: SetAuthority (6) ATA / Mint Ownership Theft
        if (tokDisc === 6 && data.length >= 3) {
          const authType = data[1];
          const hasNewAuth = data[2];
          const newAuthB58 =
            hasNewAuth === 1 && data.length >= 35
              ? encodeB58(data.subarray(3, 35))
              : "NONE";
          if (newAuthB58 !== userPubkeyB58) {
            threats.push({
              rule: "RULE_02_NO_SET_AUTHORITY",
              severity: "CRITICAL",
              ixIndex: i,
              detail: `Blocked SPL SetAuthority (type=${authType}) attempting to transfer token account authority to ${newAuthB58}.`
            });
          }
        }

        // RULE_06: Approve (4) / ApproveChecked (13) Unlimited Token Delegation
        if (tokDisc === 4 || tokDisc === 13) {
          const delegateAcc = ix.accounts[1]?.pubkeyB58 || "UNKNOWN_DELEGATE";
          threats.push({
            rule: "RULE_06_NO_TOKEN_DELEGATE",
            severity: "CRITICAL",
            ixIndex: i,
            detail: `Blocked SPL Token Approve/ApproveChecked granting delegation to ${delegateAcc}.`
          });
        }

        // RULE_08a: CloseAccount (9) rent/WSOL theft
        if (tokDisc === 9) {
          const closedAcc = ix.accounts[0]?.pubkeyB58;
          const destAcc = ix.accounts[1]?.pubkeyB58;
          const ownerAcc = ix.accounts[2]?.pubkeyB58;
          if (
            (ownerAcc === userPubkeyB58 || userAtas.has(closedAcc)) &&
            destAcc !== userPubkeyB58 &&
            !allowedTokenDestSet.has(destAcc)
          ) {
            threats.push({
              rule: "RULE_08_CLOSE_ACCOUNT_RENT_STEAL",
              severity: "CRITICAL",
              ixIndex: i,
              detail: `Blocked CloseAccount redirect attempting to send SOL/WSOL rent from ${closedAcc} to ${destAcc}.`
            });
          }
        }

        // RULE_08b: InitializeAccount (1 / 16 / 18) fake WSOL external owner trap
        if (tokDisc === 1 || tokDisc === 16 || tokDisc === 18) {
          let initOwnerB58 = null;
          if (tokDisc === 1) {
            initOwnerB58 = ix.accounts[2]?.pubkeyB58;
          } else if (data.length >= 33) {
            initOwnerB58 = encodeB58(data.subarray(1, 33));
          }
          if (
            initOwnerB58 &&
            initOwnerB58 !== userPubkeyB58 &&
            !CANONICAL_SOLANA_PROGRAMS.has(initOwnerB58)
          ) {
            threats.push({
              rule: "RULE_08_FAKE_WSOL_INIT_OWNER",
              severity: "CRITICAL",
              ixIndex: i,
              detail: `Blocked fake WSOL/Token initialization assigning external owner ${initOwnerB58}.`
            });
          }
        }
      }

      // 3. UNKNOWN CPI WRITABLE QUARANTINE (RULE_03 - Simulation-Spoofing Defense)
      if (!CANONICAL_SOLANA_PROGRAMS.has(prog)) {
        invokesUnverifiedProgram = true;
        const userIsTxSigner = decoded.staticAccounts.some(
          (a) => a.isSigner && a.pubkeyB58 === userPubkeyB58
        );
        const exposesUserWritableOrSigner =
          userIsTxSigner ||
          ix.accounts.some(
            (a) =>
              a.isWritable ||
              a.isSigner ||
              a.pubkeyB58 === userPubkeyB58 ||
              userAtas.has(a.pubkeyB58)
          );
        if (exposesUserWritableOrSigner && !context.allowExternalDappWithGuard) {
          threats.push({
            rule: "RULE_03_UNKNOWN_CPI_WRITABLE_QUARANTINE",
            severity: "CRITICAL",
            ixIndex: i,
            detail: `Unverified program ${prog} requests signer/writable access. Blocked to prevent simulation-spoofing CPI drains (enable Balance-Floor Guard to proceed).`
          });
        }

        const txIncludesTokenProgram =
          ix.accounts.some(
            (a) => a.pubkeyB58 === SPL_TOKEN_PROGRAM_ID || a.pubkeyB58 === TOKEN_2022_PROGRAM_ID
          ) ||
          decoded.staticAccounts.some(
            (a) => a.pubkeyB58 === SPL_TOKEN_PROGRAM_ID || a.pubkeyB58 === TOKEN_2022_PROGRAM_ID
          );
        const hasUnprotectedWritableWithTokenProg =
          txIncludesTokenProgram &&
          userAtas.size === 0 &&
          protectedAtaSet.size === 0 &&
          ix.accounts.some((a) => a.isWritable && a.pubkeyB58 !== userPubkeyB58);

        if (
          context.requireTokenInventory &&
          (!Array.isArray(context.userTokenAtas) || hasUnprotectedWritableWithTokenProg) &&
          ix.accounts.some((a) => a.pubkeyB58 === userPubkeyB58 && a.isSigner)
        ) {
          threats.push({
            rule: "RULE_03F_UNKNOWN_CPI_TOKEN_INVENTORY_REQUIRED",
            severity: "HIGH",
            ixIndex: i,
            detail: `Unverified program ${prog} receives user signature without verified token-account inventory (userTokenAtas).`
          });
        }

        const unprotectedWritableUserAta = ix.accounts.find(
          (a) =>
            a.isWritable &&
            userAtas.has(a.pubkeyB58) &&
            !protectedAtaSet.has(a.pubkeyB58)
        );
        if (unprotectedWritableUserAta) {
          threats.push({
            rule: "RULE_03D_UNPROTECTED_USER_ATA_IN_UNKNOWN_CPI",
            severity: "CRITICAL",
            ixIndex: i,
            detail: `Unverified program ${prog} requests writable access to token account ${unprotectedWritableUserAta.pubkeyB58} without a Token Balance-Floor Guard.`
          });
        }
      }
    }

    if (totalDirectSolOutLamports > maxApprovedLamports) {
      threats.push({
        rule: "RULE_08_EXCESSIVE_SOL_SWEEP",
        severity: "CRITICAL",
        detail: `Transaction transfers ${Number(totalDirectSolOutLamports) / 1e9} SOL, exceeding approved ceiling of ${Number(maxApprovedLamports) / 1e9} SOL.`
      });
    }

    const inspectLatencyUs = Number(process.hrtime.bigint() - t0) / 1e3;

    if (threats.length > 0) {
      return {
        safe: false,
        tier: "BLOCKED_DRAINER_ATTACK",
        ruleTriggered: threats[0].rule,
        reason: threats[0].detail,
        threats,
        warnings,
        totalDirectSolOutLamports,
        inspectLatencyUs: Number(inspectLatencyUs.toFixed(2)),
        decodedSummary: {
          version: decoded.version,
          feePayer: decoded.feePayerB58,
          recentBlockhash: decoded.recentBlockhashB58,
          instructionCount: decoded.instructions.length
        }
      };
    }

    return {
      safe: true,
      tier: invokesUnverifiedProgram ? "EXTERNAL_DAPP_GUARDED" : "VERIFIED_SAFE",
      ruleTriggered: null,
      reason: invokesUnverifiedProgram
        ? "External dApp permitted only with On-Chain Balance-Floor Guard attached"
        : "Verified canonical Solana instruction bytecode",
      threats: [],
      warnings,
      requiresOnChainBalanceFloorGuard: invokesUnverifiedProgram,
      totalDirectSolOutLamports,
      inspectLatencyUs: Number(inspectLatencyUs.toFixed(2)),
      decoded
    };
  }

  /**
   * RULE_05: signMessage() Raw TransactionMessage Bit-Flip Phishing Detector.
   */
  static inspectSignMessagePayload(messagePayload, userPubkeyB58) {
    const t0 = process.hrtime.bigint();
    const buf =
      typeof messagePayload === "string"
        ? Buffer.from(messagePayload, "utf8")
        : Buffer.from(messagePayload);
    const userPubBuf = decodeB58(userPubkeyB58);

    if (buf.length >= 68 && buf[0] === 0x80) {
      const potentialPayer = buf.subarray(5, 37);
      if (potentialPayer.equals(userPubBuf) || buf[1] >= 1) {
        return {
          safe: false,
          ruleTriggered: "RULE_05_SIGN_MESSAGE_TX_BITFLIP",
          reason:
            "CRITICAL PHISHING BLOCK: Raw Versioned Solana TransactionMessage (0x80) passed into signMessage().",
          inspectLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
        };
      }
    }

    try {
      const parsed = decodeWireTransactionFast(buf, { isMessageOnly: true });
      if (
        parsed.instructions.length > 0 &&
        parsed.staticAccounts.some((a) => a.pubkeyB58 === userPubkeyB58)
      ) {
        return {
          safe: false,
          ruleTriggered: "RULE_05_SIGN_MESSAGE_TX_BITFLIP",
          reason:
            "CRITICAL PHISHING BLOCK: Payload inside signMessage() parses as a Solana TransactionMessage listing your wallet.",
          inspectLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
        };
      }
    } catch (_) {}

    if (buf.length >= 68 && buf.subarray(4, 36).equals(userPubBuf)) {
      return {
        safe: false,
        ruleTriggered: "RULE_05_SIGN_MESSAGE_TX_BITFLIP",
        reason:
          "CRITICAL PHISHING BLOCK: Binary payload contains your 32-byte public key at the legacy Solana fee-payer offset [4..36].",
        inspectLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
      };
    }

    return {
      safe: true,
      ruleTriggered: null,
      reason: "Verified off-chain message (domain-separated from Solana wire transactions)",
      domainSeparatedPayload: BytecodeDrainerFirewall.wrapSafeOffchainMessage(buf),
      inspectLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
    };
  }

  static wrapSafeOffchainMessage(msgBuf) {
    const prefix = Buffer.from("\xffsolana offchain\x00\x01", "binary");
    if (msgBuf.subarray(0, 16).equals(prefix.subarray(0, 16))) {
      return msgBuf;
    }
    const lenBuf = Buffer.allocUnsafe(2);
    lenBuf.writeUInt16LE(msgBuf.length, 0);
    return Buffer.concat([prefix, lenBuf, msgBuf]);
  }

  static buildRevokeDelegateIx(tokenAccountB58, ownerPubkeyB58, isToken2022 = false) {
    return {
      programId: isToken2022 ? TOKEN_2022_PROGRAM_ID : SPL_TOKEN_PROGRAM_ID,
      keys: [
        { pubkey: tokenAccountB58, isSigner: false, isWritable: true },
        { pubkey: ownerPubkeyB58, isSigner: true, isWritable: false }
      ],
      data: Buffer.from([5])
    };
  }

  /**
   * RULE_07: Audits raw Token-2022 Mint Account TLV extension bytes.
   */
  static auditToken2022MintAccountData(mintAccountData) {
    const t0 = process.hrtime.bigint();
    const buf = Buffer.isBuffer(mintAccountData)
      ? mintAccountData
      : Buffer.from(mintAccountData);

    const findings = [];
    if (buf.length <= 166) {
      return {
        safe: true,
        isToken2022WithExtensions: false,
        findings: [],
        auditLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
      };
    }

    let offset = 166;
    while (offset + 4 <= buf.length) {
      const extType = buf.readUInt16LE(offset);
      const extLen = buf.readUInt16LE(offset + 2);
      offset += 4;
      if (extType === 0) break;
      if (offset + extLen > buf.length) break;

      const extData = buf.subarray(offset, offset + extLen);
      offset += extLen;

      if (extType === 12) {
        const delegateB58 =
          extData.length >= 32 ? encodeB58(extData.subarray(extData.length - 32)) : "ACTIVE";
        if (delegateB58 !== SYSTEM_PROGRAM_ID) {
          findings.push({
            rule: "RULE_07_PERMANENT_DELEGATE_TRAP",
            severity: "CRITICAL",
            extensionType: 12,
            detail: `Token-2022 PermanentDelegate is active (${delegateB58}). Authority can transfer or burn user tokens unilaterally.`
          });
        }
      } else if (extType === 9) {
        findings.push({
          rule: "RULE_07_NON_TRANSFERABLE_TOKEN",
          severity: "CRITICAL",
          extensionType: 9,
          detail: "Token-2022 NonTransferable extension active. Tokens cannot be transferred out once acquired."
        });
      } else if (extType === 14) {
        const hookProgB58 =
          extData.length >= 64 ? encodeB58(extData.subarray(32, 64)) : "CUSTOM_HOOK";
        if (hookProgB58 !== SYSTEM_PROGRAM_ID) {
          findings.push({
            rule: "RULE_07_TRANSFER_HOOK_ACTIVE",
            severity: "HIGH",
            extensionType: 14,
            detail: `Token-2022 TransferHook active (Program: ${hookProgB58}). Custom CPI executes on every transfer.`
          });
        }
      } else if (extType === 6 && extData.length >= 1 && extData[0] === 2) {
        findings.push({
          rule: "RULE_07_DEFAULT_FROZEN_STATE",
          severity: "CRITICAL",
          extensionType: 6,
          detail: "Token-2022 DefaultAccountState is FROZEN."
        });
      } else if (extType === 1 && extData.length >= 108) {
        const feeBps = extData.readUInt16LE(106);
        if (feeBps >= 5000) {
          findings.push({
            rule: "RULE_07_EXCESSIVE_TRANSFER_FEE",
            severity: "CRITICAL",
            extensionType: 1,
            detail: `Token-2022 TransferFee is set to ${(feeBps / 100).toFixed(2)}%.`
          });
        }
      }
    }

    const hasCritical = findings.some((f) => f.severity === "CRITICAL");
    return {
      safe: !hasCritical,
      isToken2022WithExtensions: true,
      findings,
      auditLatencyUs: Number((Number(process.hrtime.bigint() - t0) / 1e3).toFixed(2))
    };
  }

  /**
   * RULE_09: Vanity Address Poisoning & Visual Homoglyph Detector.
   */
  static inspectAddressPoisoningRisk(targetAddressB58, trustedAddressesB58 = []) {
    if (trustedAddressesB58.includes(targetAddressB58)) {
      return {
        safe: true,
        isTrustedExactMatch: true,
        poisoningDetected: false,
        reason: "Exact match with verified address book"
      };
    }

    const normalizeHomoglyphs = (str) =>
      String(str || "")
        .toLowerCase()
        .replace(/[0o]/g, "0")
        .replace(/[1il]/g, "1");

    const normTarget = normalizeHomoglyphs(targetAddressB58);

    for (const trusted of trustedAddressesB58) {
      if (!trusted || trusted === targetAddressB58) continue;
      const normTrusted = normalizeHomoglyphs(trusted);

      let prefixMatchLen = 0;
      const minLen = Math.min(normTarget.length, normTrusted.length);
      while (
        prefixMatchLen < minLen &&
        normTarget[prefixMatchLen] === normTrusted[prefixMatchLen]
      ) {
        prefixMatchLen++;
      }

      let suffixMatchLen = 0;
      while (
        suffixMatchLen < minLen &&
        normTarget[normTarget.length - 1 - suffixMatchLen] ===
          normTrusted[normTrusted.length - 1 - suffixMatchLen]
      ) {
        suffixMatchLen++;
      }

      const isDualEndLookalike =
        (prefixMatchLen >= 3 && suffixMatchLen >= 3) ||
        (prefixMatchLen >= 4 && suffixMatchLen >= 2) ||
        (prefixMatchLen >= 2 && suffixMatchLen >= 4);
      const isSingleEndDeepVanity = prefixMatchLen >= 5 || suffixMatchLen >= 5;

      if (isDualEndLookalike || isSingleEndDeepVanity) {
        return {
          safe: false,
          isTrustedExactMatch: false,
          poisoningDetected: true,
          ruleTriggered: "RULE_09_VANITY_ADDRESS_POISONING",
          spoofedTrustedAddress: trusted,
          prefixMatchLen,
          suffixMatchLen,
          reason: `ADDRESS POISONING ALERT: Target ${targetAddressB58} mimics ${prefixMatchLen} leading and ${suffixMatchLen} trailing characters of trusted address ${trusted}.`
        };
      }
    }

    return {
      safe: true,
      isTrustedExactMatch: false,
      poisoningDetected: false,
      reason: "External address has no vanity lookalike collision"
    };
  }

  /**
   * RULE_10: Native On-Chain Balance-Floor Guard Injector.
   */
  static buildOnChainBalanceFloorGuard(params) {
    if (
      params === null ||
      typeof params !== "object" ||
      params.currentBalanceLamports === undefined ||
      params.currentBalanceLamports === null
    ) {
      throw new Error(
        "EXPLICIT_VERIFIED_BALANCE_REQUIRED: currentBalanceLamports must be explicitly provided to buildOnChainBalanceFloorGuard"
      );
    }

    const currentBal = BigInt(params.currentBalanceLamports);
    const maxSpend = BigInt(params.maxApprovedSpendLamports ?? 0n);
    const feeBuf = BigInt(params.feeBufferLamports ?? 50_000n);

    if (currentBal <= 0n || maxSpend + feeBuf >= currentBal) {
      throw new Error(
        "Cannot build Balance-Floor Guard when maxApprovedSpend + feeBuffer >= currentBalanceLamports"
      );
    }

    const minRemainingLamports = currentBal - maxSpend - feeBuf;
    const minProtectedReserveLamports = BigInt(
      params.minProtectedReserveLamports ?? 10_000_000n
    );
    if (minRemainingLamports < minProtectedReserveLamports) {
      throw new Error(
        `BALANCE_FLOOR_COLLAPSE_BLOCKED: Enforced balance floor (${minRemainingLamports} lamports) is below the minimum ${minProtectedReserveLamports} lamports safety reserve`
      );
    }

    const guardData = Buffer.allocUnsafe(12);
    guardData.writeUInt32LE(2, 0);
    guardData.writeBigUInt64LE(minRemainingLamports, 4);

    const guardTransferOutIx = {
      programId: SYSTEM_PROGRAM_ID,
      keys: [
        { pubkey: params.userHotWalletB58, isSigner: true, isWritable: true },
        { pubkey: params.userSafeVaultB58, isSigner: false, isWritable: true }
      ],
      data: guardData
    };

    const guardTransferBackIx = {
      programId: SYSTEM_PROGRAM_ID,
      keys: [
        { pubkey: params.userSafeVaultB58, isSigner: true, isWritable: true },
        { pubkey: params.userHotWalletB58, isSigner: false, isWritable: true }
      ],
      data: Buffer.from(guardData)
    };

    const tokenFloorGuardIxs = [];
    const tokenDelegateRevokeIxs = [];
    if (Array.isArray(params.protectedTokenAtas)) {
      for (const tok of params.protectedTokenAtas) {
        if (!tok || !tok.ataPubkeyB58) continue;
        tokenFloorGuardIxs.push(
          BytecodeDrainerFirewall.buildTokenBalanceFloorGuardIx({
            userTokenAtaB58: tok.ataPubkeyB58,
            userOwnerPubkeyB58: params.userHotWalletB58,
            minRemainingRawAmount: BigInt(tok.minRemainingRawAmount ?? 1n),
            isToken2022: Boolean(tok.isToken2022)
          })
        );
        tokenDelegateRevokeIxs.push(
          BytecodeDrainerFirewall.buildRevokeDelegateIx(
            tok.ataPubkeyB58,
            params.userHotWalletB58,
            Boolean(tok.isToken2022)
          )
        );
      }
    }

    return {
      protectedWallet: params.userHotWalletB58,
      safeVaultAnchor: params.userSafeVaultB58,
      currentBalanceLamports: currentBal,
      maxApprovedSpendLamports: maxSpend,
      enforcedMinRemainingLamports: minRemainingLamports,
      svmInvariant: `post_balance(${params.userHotWalletB58.slice(0, 6)}...) >= ${minRemainingLamports} lamports`,
      singleSignerGuardIx: guardTransferOutIx,
      roundTripDualSignerGuardIxs: [
        guardTransferOutIx,
        guardTransferBackIx,
        ...tokenFloorGuardIxs,
        ...tokenDelegateRevokeIxs
      ],
      tokenFloorGuardIxs,
      tokenDelegateRevokeIxs
    };
  }

  static buildTokenBalanceFloorGuardIx({
    userTokenAtaB58,
    userOwnerPubkeyB58,
    minRemainingRawAmount,
    isToken2022 = false
  }) {
    const data = Buffer.allocUnsafe(9);
    data[0] = 3;
    data.writeBigUInt64LE(BigInt(minRemainingRawAmount), 1);
    return {
      programId: isToken2022 ? TOKEN_2022_PROGRAM_ID : SPL_TOKEN_PROGRAM_ID,
      keys: [
        { pubkey: userTokenAtaB58, isSigner: false, isWritable: true },
        { pubkey: userTokenAtaB58, isSigner: false, isWritable: true },
        { pubkey: userOwnerPubkeyB58, isSigner: true, isWritable: false }
      ],
      data
    };
  }
}

module.exports = {
  BytecodeDrainerFirewall,
  decodeWireTransactionFast,
  readCompactU16,
  CANONICAL_SOLANA_PROGRAMS,
  VERIFIED_WHITELIST_PROGRAMS: CANONICAL_SOLANA_PROGRAMS,
  SYSTEM_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  ATA_PROGRAM_ID,
  MEMO_PROGRAM_ID,
  MEMO_V1_PROGRAM_ID
};
