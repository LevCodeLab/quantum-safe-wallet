"use strict";

/**
 * quantum-safe-wallet - Part 4: Loopback JSON-RPC 2.0 Wallet-Standard Server
 * ==========================================================================
 * Local 127.0.0.1 JSON-RPC 2.0 wallet bridge with 256-bit bearer token
 * authentication (X-QSafe-Auth-Token), DNS-rebinding & Origin guards,
 * mutex-serialized PBKDF2 unlock rate-limiting, COLD vs HOT tier isolation,
 * and sticky server-side balance-floor & token-inventory policy.
 */

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  VaultCryptoEngine,
  WotsXmssEngine,
  encodeB58,
  signEd25519Seed32Native
} = require("./vault_crypto");
const { BytecodeDrainerFirewall } = require("./drainer_firewall");
const { compileV0MessageFast, guardAndSignTransaction } = require("./tx_builder");

const INTERNAL_POLICY = Symbol("qsafe.internalSigningPolicy");
const MAX_BATCH_TRANSACTIONS = 64;
const AUTH_HEADER_NAME = "X-QSafe-Auth-Token";
const AUTH_HEADER_LOWER = "x-qsafe-auth-token";

class QSafeWalletBridge {
  constructor(options = {}) {
    this.options = options;
    this.vault = null;
    this.connectedTier = "HOT";
    this.connectedBurnerIndex = 0;
    this.currentSlot = options.initialSlot ?? 320_000_000;
    this.cachedBlockhashB58 =
      options.initialBlockhashB58 ||
      encodeB58(crypto.createHash("sha256").update("QSAFE_INITIAL_BLOCKHASH_SEED").digest());
    this.trustedAddresses = new Set();

    // 256-bit cryptographic session bearer token
    this.sessionAuthToken =
      options.sessionAuthToken || crypto.randomBytes(32).toString("hex");

    // Mutex-serialized PBKDF2 unlock rate-limiter
    this.failedUnlockAttempts = 0;
    this.maxFailedUnlockAttempts = options.maxFailedUnlockAttempts ?? 5;
    this.unlockLockoutDurationMs = options.unlockLockoutDurationMs ?? 30_000;
    this.unlockLockoutUntilMs = 0;
    this._unlockQueue = Promise.resolve();

    // Server-side SOL spend ceiling (tightening allowed per request; loosening requires passphrase)
    this.policy = {
      maxPerTxSolLamports: BigInt(options.maxPerTxSolLamports ?? 2_000_000_000n)
    };

    // Sticky ATA inventory & balance-floor ratchet
    this.knownUserTokenAtas = new Set();
    this.knownProtectedTokenFloors = new Map();
    this.knownWalletBalanceFloorLamports = new Map();
  }

  _resetStickySecurityTrackers() {
    this.knownUserTokenAtas.clear();
    this.knownProtectedTokenFloors.clear();
    this.knownWalletBalanceFloorLamports.clear();
  }

  _runSerializedUnlock(fn) {
    const next = this._unlockQueue.then(fn, fn);
    this._unlockQueue = next.catch(() => {});
    return next;
  }

  async _verifyPassphraseCounted(passphrase) {
    if (Date.now() < this.unlockLockoutUntilMs) {
      const waitSec = Math.ceil((this.unlockLockoutUntilMs - Date.now()) / 1000);
      throw new Error(
        `VAULT_UNLOCK_RATE_LIMITED: Too many failed passphrase attempts. Locked out for ${waitSec}s.`
      );
    }
    const ok =
      Boolean(this.vault) &&
      typeof passphrase === "string" &&
      (await this.vault.verifyPassphraseAsync(passphrase));
    if (!ok) {
      this.failedUnlockAttempts += 1;
      if (this.failedUnlockAttempts >= this.maxFailedUnlockAttempts) {
        this.unlockLockoutUntilMs = Date.now() + this.unlockLockoutDurationMs;
      }
    } else {
      this.failedUnlockAttempts = 0;
    }
    return ok;
  }

  _verifyPassphraseRateLimited(passphrase) {
    return this._runSerializedUnlock(() => this._verifyPassphraseCounted(passphrase));
  }

  _assertDappSigningTier(tier, noun) {
    if (tier === "COLD") {
      throw new Error(
        `COLD_VAULT_DAPP_SIGNING_FORBIDDEN: Post-quantum COLD vault never blind-signs external dApp ${noun}; use HOT or BURNER tier`
      );
    }
    if (tier !== "HOT" && tier !== "BURNER") {
      throw new Error(
        `INVALID_TIER: dApp signing supports only HOT or BURNER (got ${JSON.stringify(tier)})`
      );
    }
  }

  _assertValidBurnerIndex(burnerIndex) {
    const burners = this.vault.getPublicVaultSummary().burnerPool.burners || [];
    if (!Number.isInteger(burnerIndex) || burnerIndex < 0 || burnerIndex >= burners.length) {
      throw new Error(`INVALID_BURNER_INDEX: ${String(burnerIndex)} is outside derived burner pool`);
    }
  }

  _getOwnVaultAddressesSet() {
    if (!this.vault) return new Set();
    const summary = this.vault.getPublicVaultSummary();
    return new Set(
      [
        summary.primaryHotWallet.pubkey,
        summary.primaryHotWallet.balanceFloorGuardAnchorPubkey,
        summary.quantumColdVault.pubkey,
        summary.quantumColdVault.hashLockedQuantumPdaVault,
        ...(summary.burnerPool.burners || []).map((b) => b.pubkey)
      ].filter(Boolean)
    );
  }

  _requireUnlocked() {
    if (!this.vault) {
      throw new Error("WALLET_LOCKED: Unlock or create a Quantum-Safe Vault first");
    }
  }

  async _resolveSigningPolicy(params) {
    let overrideOk = false;
    if (params.policyOverridePassphrase !== undefined) {
      overrideOk = await this._verifyPassphraseRateLimited(params.policyOverridePassphrase);
      if (!overrideOk) {
        throw new Error("POLICY_OVERRIDE_REAUTH_FAILED: Invalid vault passphrase for policy override");
      }
    }
    const cap = this.policy.maxPerTxSolLamports;
    let requested =
      params.maxApprovedSolLamports !== undefined ? BigInt(params.maxApprovedSolLamports) : cap;
    if (requested < 0n) requested = 0n;
    const own = this._getOwnVaultAddressesSet();
    return {
      overrideOk,
      maxApprovedSolLamports: overrideOk ? requested : requested < cap ? requested : cap,
      allowDirectTokenTransfers: overrideOk && Boolean(params.allowDirectTokenTransfers),
      allowTokenBurn: overrideOk && Boolean(params.allowTokenBurn),
      allowedTokenTransferDestinations: (Array.isArray(params.allowedTokenTransferDestinations)
        ? params.allowedTokenTransferDestinations
        : []
      ).filter((a) => overrideOk || own.has(a))
    };
  }

  _recordAndResolveStickyInventory(params, overrideOk = false) {
    if (overrideOk && Array.isArray(params.userTokenAtas)) {
      this.knownUserTokenAtas = new Set(params.userTokenAtas.filter(Boolean));
    } else if (Array.isArray(params.userTokenAtas)) {
      for (const a of params.userTokenAtas) {
        if (a) this.knownUserTokenAtas.add(a);
      }
    }

    if (overrideOk && Array.isArray(params.protectedTokenAtas)) {
      this.knownProtectedTokenFloors.clear();
    }
    if (Array.isArray(params.protectedTokenAtas)) {
      for (const p of params.protectedTokenAtas) {
        if (!p || !p.ataPubkeyB58) continue;
        this.knownUserTokenAtas.add(p.ataPubkeyB58);
        const raw = BigInt(p.minRemainingRawAmount ?? 1n);
        const prev = this.knownProtectedTokenFloors.get(p.ataPubkeyB58);
        if (!prev || overrideOk || raw > prev.minRemainingRawAmount) {
          this.knownProtectedTokenFloors.set(p.ataPubkeyB58, {
            ataPubkeyB58: p.ataPubkeyB58,
            minRemainingRawAmount: raw,
            isToken2022: Boolean(p.isToken2022)
          });
        }
      }
    }

    const effectiveUserTokenAtas = Array.isArray(params.userTokenAtas)
      ? Array.from(new Set([...params.userTokenAtas.filter(Boolean), ...this.knownUserTokenAtas]))
      : undefined;

    const mergedProtectedMap = new Map(this.knownProtectedTokenFloors);
    for (const p of params.protectedTokenAtas || []) {
      if (!p || !p.ataPubkeyB58) continue;
      const raw = BigInt(p.minRemainingRawAmount ?? 1n);
      const existing = mergedProtectedMap.get(p.ataPubkeyB58);
      if (!existing || overrideOk || raw >= existing.minRemainingRawAmount) {
        mergedProtectedMap.set(p.ataPubkeyB58, {
          ataPubkeyB58: p.ataPubkeyB58,
          minRemainingRawAmount: raw,
          isToken2022: Boolean(p.isToken2022)
        });
      }
    }

    return {
      effectiveUserTokenAtas,
      effectiveProtectedTokenAtas: Array.from(mergedProtectedMap.values())
    };
  }

  async handleRpcMethod(method, params = {}) {
    switch (method) {
      case "wallet_createVault": {
        if (this.vault) {
          if (
            typeof params.currentPassphrase !== "string" ||
            !(await this._verifyPassphraseRateLimited(params.currentPassphrase))
          ) {
            throw new Error(
              "VAULT_REPLACE_REAUTH_REQUIRED: Creating a new vault while one is unlocked requires currentPassphrase"
            );
          }
        }
        if (params.allowOverwrite && params.vaultFilePath) {
          let exists = false;
          try {
            exists = fs.existsSync(path.resolve(String(params.vaultFilePath)));
          } catch (_) {}
          if (exists) {
            const proven = await this._runSerializedUnlock(async () => {
              if (Date.now() < this.unlockLockoutUntilMs) {
                throw new Error("VAULT_UNLOCK_RATE_LIMITED: Too many failed passphrase attempts.");
              }
              try {
                const old = await VaultCryptoEngine.loadVaultAsync(
                  params.vaultFilePath,
                  params.existingVaultPassphrase
                );
                old.lockAndDestroy();
                this.failedUnlockAttempts = 0;
                return true;
              } catch (_) {
                this.failedUnlockAttempts += 1;
                if (this.failedUnlockAttempts >= this.maxFailedUnlockAttempts) {
                  this.unlockLockoutUntilMs = Date.now() + this.unlockLockoutDurationMs;
                }
                return false;
              }
            });
            if (!proven) {
              throw new Error(
                "VAULT_OVERWRITE_REAUTH_REQUIRED: Overwriting an existing vault file requires existingVaultPassphrase"
              );
            }
          }
        }
        if (this.vault) this.vault.lockAndDestroy();

        this.vault = await VaultCryptoEngine.createNewVaultAsync(params.passphrase, {
          masterSeed32: params.masterSeedHex
            ? Buffer.from(params.masterSeedHex, "hex")
            : undefined,
          importedHotSecretKey: params.importedHotSecretKey,
          vaultFilePath: params.vaultFilePath,
          allowOverwrite: Boolean(params.allowOverwrite),
          kdfIterations: params.kdfIterations ?? this.options.kdfIterations
        });
        this.failedUnlockAttempts = 0;
        this.unlockLockoutUntilMs = 0;
        this._resetStickySecurityTrackers();

        const summary = this.vault.getPublicVaultSummary();
        this.trustedAddresses.add(summary.quantumColdVault.pubkey);
        this.trustedAddresses.add(summary.primaryHotWallet.pubkey);
        this.trustedAddresses.add(summary.burnerPool.activeBurnerPubkey);

        return {
          status: "VAULT_CREATED_AND_UNLOCKED",
          summary
        };
      }

      case "wallet_unlockVault": {
        return this._runSerializedUnlock(async () => {
          if (Date.now() < this.unlockLockoutUntilMs) {
            const waitSec = Math.ceil((this.unlockLockoutUntilMs - Date.now()) / 1000);
            throw new Error(
              `VAULT_UNLOCK_RATE_LIMITED: Too many failed unlock attempts. Locked out for ${waitSec}s.`
            );
          }

          let unlockedVault;
          try {
            unlockedVault = await VaultCryptoEngine.loadVaultAsync(
              params.envelope || params.vaultFilePath,
              params.passphrase
            );
          } catch (err) {
            this.failedUnlockAttempts += 1;
            if (this.failedUnlockAttempts >= this.maxFailedUnlockAttempts) {
              this.unlockLockoutUntilMs = Date.now() + this.unlockLockoutDurationMs;
            }
            throw err;
          }

          if (
            this.vault &&
            unlockedVault.xmssEngine.masterRootHex !== this.vault.xmssEngine.masterRootHex
          ) {
            let authorized = false;
            if (typeof params.currentPassphrase === "string") {
              authorized = await this._verifyPassphraseCounted(params.currentPassphrase);
            }
            if (!authorized) {
              unlockedVault.lockAndDestroy();
              throw new Error(
                "VAULT_SWITCH_REAUTH_REQUIRED: Switching to a different vault requires currentPassphrase"
              );
            }
          }

          if (this.vault) this.vault.lockAndDestroy();
          this.failedUnlockAttempts = 0;
          this.unlockLockoutUntilMs = 0;
          this._resetStickySecurityTrackers();
          this.vault = unlockedVault;

          const summary = this.vault.getPublicVaultSummary();
          this.trustedAddresses.add(summary.quantumColdVault.pubkey);
          this.trustedAddresses.add(summary.primaryHotWallet.pubkey);
          return {
            status: "VAULT_UNLOCKED",
            summary
          };
        });
      }

      case "wallet_lockVault": {
        this._resetStickySecurityTrackers();
        if (this.vault) {
          this.vault.lockAndDestroy();
          this.vault = null;
        }
        return { status: "VAULT_LOCKED_MEMORY_ZEROIZED" };
      }

      case "wallet_connect": {
        this._requireUnlocked();
        const tier = params.tier || "HOT";
        if (tier !== "HOT" && tier !== "COLD" && tier !== "BURNER") {
          throw new Error(`INVALID_TIER: unsupported tier ${JSON.stringify(tier)}`);
        }
        if (tier === "BURNER" && params.burnerIndex !== undefined) {
          this._assertValidBurnerIndex(params.burnerIndex);
        }
        this.connectedTier = tier;
        const summary = this.vault.getPublicVaultSummary();
        let activePubkey = summary.primaryHotWallet.pubkey;
        if (tier === "COLD") {
          activePubkey = summary.quantumColdVault.pubkey;
        } else if (tier === "BURNER") {
          const idx =
            typeof params.burnerIndex === "number"
              ? params.burnerIndex
              : summary.burnerPool.activeBurnerIndex;
          this.connectedBurnerIndex = idx;
          activePubkey = summary.burnerPool.burners[idx]?.pubkey || activePubkey;
        }
        return {
          connected: true,
          activeTier: tier,
          publicKey: activePubkey,
          slot: this.currentSlot,
          quantumScheme: "QSAFE_WOTS_PLUS_XMSS_SHA256_W16_C67",
          summary
        };
      }

      case "wallet_signTransaction": {
        this._requireUnlocked();
        const requestedTier = params.tier || this.connectedTier;
        this._assertDappSigningTier(requestedTier, "transactions");
        const signBurnerIndex = params.burnerIndex ?? this.connectedBurnerIndex;
        if (requestedTier === "BURNER") this._assertValidBurnerIndex(signBurnerIndex);

        const rawTxBuf = Buffer.isBuffer(params.transactionBase64)
          ? params.transactionBase64
          : Buffer.from(params.transactionBase64, "base64");

        const policy = params[INTERNAL_POLICY] || (await this._resolveSigningPolicy(params));
        const summary = this.vault.getPublicVaultSummary();
        const activeSignerPubkey =
          requestedTier === "BURNER"
            ? summary.burnerPool.burners[signBurnerIndex]?.pubkey
            : summary.primaryHotWallet.pubkey;

        const { effectiveUserTokenAtas, effectiveProtectedTokenAtas } =
          this._recordAndResolveStickyInventory(params, Boolean(policy.overrideOk));

        let effectiveCurrentWalletBalanceLamports = params.currentWalletBalanceLamports;
        if (
          effectiveCurrentWalletBalanceLamports !== undefined &&
          effectiveCurrentWalletBalanceLamports !== null
        ) {
          const callerBal = BigInt(effectiveCurrentWalletBalanceLamports);
          const knownFloor = this.knownWalletBalanceFloorLamports.get(activeSignerPubkey) || 0n;
          if (!policy.overrideOk && knownFloor > 0n && callerBal < knownFloor) {
            const underreportReason = `Blocked balance-floor under-reporting: supplied currentWalletBalanceLamports (${callerBal}) is below tracked wallet floor (${knownFloor}). Pass policyOverridePassphrase to lower.`;
            return {
              approved: false,
              status: "BLOCKED_BY_DRAINER_FIREWALL",
              ruleTriggered: "RULE_10_BALANCE_FLOOR_UNDERREPORT_BLOCKED",
              reason: underreportReason,
              threats: [
                {
                  rule: "RULE_10_BALANCE_FLOOR_UNDERREPORT_BLOCKED",
                  severity: "CRITICAL",
                  detail: underreportReason
                }
              ],
              inspectLatencyUs: 0
            };
          }
          effectiveCurrentWalletBalanceLamports = callerBal;
        }

        const res = guardAndSignTransaction(this.vault, rawTxBuf, {
          tier: requestedTier,
          burnerIndex: signBurnerIndex,
          slot: this.currentSlot,
          userTokenAtas: effectiveUserTokenAtas,
          requireTokenInventory: true,
          trustedAddresses: Array.from(this.trustedAddresses),
          allowedTokenTransferDestinations: policy.allowedTokenTransferDestinations,
          allowDirectTokenTransfers: policy.allowDirectTokenTransfers,
          allowTokenBurn: policy.allowTokenBurn,
          protectedTokenAtas: effectiveProtectedTokenAtas,
          currentWalletBalanceLamports: effectiveCurrentWalletBalanceLamports,
          maxApprovedSolLamports: policy.maxApprovedSolLamports,
          allowExternalDappWithGuard: params.allowExternalDappWithGuard ?? true
        });

        if (res.status === "BLOCKED_BY_DRAINER_FIREWALL") {
          return {
            approved: false,
            status: res.status,
            ruleTriggered: res.firewallAudit.ruleTriggered,
            reason: res.firewallAudit.reason,
            threats: res.firewallAudit.threats,
            inspectLatencyUs: res.firewallAudit.inspectLatencyUs
          };
        }

        if (
          effectiveCurrentWalletBalanceLamports !== undefined &&
          effectiveCurrentWalletBalanceLamports !== null
        ) {
          const postFloor =
            BigInt(effectiveCurrentWalletBalanceLamports) -
            BigInt(policy.maxApprovedSolLamports) -
            50_000n;
          if (postFloor > 0n) {
            this.knownWalletBalanceFloorLamports.set(activeSignerPubkey, postFloor);
          }
        }

        return {
          approved: true,
          status: "GUARDED_AND_SIGNED",
          firewallTier: res.firewallTier,
          publicKey: res.signerPubkey,
          signature: res.signatureBase58,
          signedTransactionBase64: res.wireTransaction.toString("base64"),
          wireBytes: res.wireBytes,
          onChainBalanceFloorGuardAttached: res.onChainBalanceFloorGuardAttached,
          balanceFloorInvariant: res.balanceFloorInvariant,
          directSolOutLamports: (res.directSolOutLamports || 0n).toString(),
          quantumProof: res.quantumProof,
          totalLatencyUs: res.totalLatencyUs
        };
      }

      case "wallet_signAllTransactions": {
        this._requireUnlocked();
        const txs = params.transactionsBase64 || [];
        if (!Array.isArray(txs) || txs.length > MAX_BATCH_TRANSACTIONS) {
          throw new Error(
            `BATCH_INVALID: transactionsBase64 must be an array of at most ${MAX_BATCH_TRANSACTIONS}`
          );
        }
        const results = [];
        const batchPolicy = params[INTERNAL_POLICY] || (await this._resolveSigningPolicy(params));
        let remainingBatchSolBudget = batchPolicy.maxApprovedSolLamports;

        for (const txB64 of txs) {
          const itemRes = await this.handleRpcMethod("wallet_signTransaction", {
            ...params,
            [INTERNAL_POLICY]: { ...batchPolicy, maxApprovedSolLamports: remainingBatchSolBudget },
            transactionBase64: txB64
          });
          results.push(itemRes);
          if (!itemRes.approved) {
            return {
              approved: false,
              status: "BATCH_ABORTED_BY_DRAINER_FIREWALL",
              failedIndex: results.length - 1,
              failedReason: itemRes.reason,
              results
            };
          }
          const spentInTx = BigInt(itemRes.directSolOutLamports || "0");
          remainingBatchSolBudget =
            remainingBatchSolBudget > spentInTx ? remainingBatchSolBudget - spentInTx : 0n;
        }
        return {
          approved: true,
          status: "BATCH_GUARDED_AND_SIGNED",
          count: results.length,
          results
        };
      }

      case "wallet_signMessage": {
        this._requireUnlocked();
        const summary = this.vault.getPublicVaultSummary();
        const tier = params.tier || this.connectedTier;
        this._assertDappSigningTier(tier, "messages");
        if (tier === "BURNER") {
          this._assertValidBurnerIndex(params.burnerIndex ?? this.connectedBurnerIndex);
        }
        const userPubkeyB58 =
          tier === "BURNER"
            ? summary.burnerPool.burners[params.burnerIndex ?? this.connectedBurnerIndex]?.pubkey
            : summary.primaryHotWallet.pubkey;

        const msgBuf = params.messageBase64
          ? Buffer.from(params.messageBase64, "base64")
          : Buffer.from(params.messageUtf8 || "", "utf8");

        const msgAudit = BytecodeDrainerFirewall.inspectSignMessagePayload(msgBuf, userPubkeyB58);
        if (!msgAudit.safe) {
          return {
            approved: false,
            status: "BLOCKED_BY_SIGN_MESSAGE_FIREWALL",
            ruleTriggered: msgAudit.ruleTriggered,
            reason: msgAudit.reason,
            inspectLatencyUs: msgAudit.inspectLatencyUs
          };
        }

        const safePayload = msgAudit.domainSeparatedPayload;
        const sig64 = this.vault._withTierSeed32(
          tier,
          params.burnerIndex ?? this.connectedBurnerIndex,
          (seed32) => signEd25519Seed32Native(seed32, safePayload)
        );
        const quantumProof = this.vault.signQuantumProof(this.currentSlot, safePayload);

        return {
          approved: true,
          status: "OFFCHAIN_MESSAGE_SIGNED_DOMAIN_SEPARATED",
          publicKey: userPubkeyB58,
          signatureBase58: encodeB58(sig64),
          domainSeparatedPayloadBase64: safePayload.toString("base64"),
          quantumProof,
          inspectLatencyUs: msgAudit.inspectLatencyUs
        };
      }

      case "qsafe_inspectTransaction": {
        this._requireUnlocked();
        const summary = this.vault.getPublicVaultSummary();
        const userPubkeyB58 = params.userPubkeyB58 || summary.primaryHotWallet.pubkey;
        const out = {};

        if (params.transactionBase64) {
          const rawBuf = Buffer.from(params.transactionBase64, "base64");
          const txAudit = BytecodeDrainerFirewall.inspectTransactionBytes(rawBuf, {
            userPubkeyB58,
            userTokenAtas: Array.isArray(params.userTokenAtas) ? params.userTokenAtas : undefined,
            requireTokenInventory: true,
            protectedTokenAtas: params.protectedTokenAtas || [],
            trustedAddresses: Array.from(this.trustedAddresses),
            maxApprovedSolLamports: params.maxApprovedSolLamports ?? this.policy.maxPerTxSolLamports,
            allowExternalDappWithGuard: Boolean(params.allowExternalDappWithGuard)
          });
          out.transactionAudit = {
            safe: txAudit.safe,
            tier: txAudit.tier,
            ruleTriggered: txAudit.ruleTriggered,
            reason: txAudit.reason,
            threats: txAudit.threats,
            warnings: txAudit.warnings,
            inspectLatencyUs: txAudit.inspectLatencyUs
          };
        }

        if (params.targetAddressB58) {
          out.addressPoisoningAudit = BytecodeDrainerFirewall.inspectAddressPoisoningRisk(
            params.targetAddressB58,
            Array.from(this.trustedAddresses)
          );
        }

        if (params.token2022MintBase64) {
          out.token2022MintAudit = BytecodeDrainerFirewall.auditToken2022MintAccountData(
            Buffer.from(params.token2022MintBase64, "base64")
          );
        }

        return out;
      }

      case "qsafe_deriveBurner": {
        this._requireUnlocked();
        const burner = this.vault.deriveNextBurner(params.label);
        this.trustedAddresses.add(burner.pubkey);
        return burner;
      }

      case "qsafe_rotateColdVault": {
        this._requireUnlocked();
        const ownAddresses = this._getOwnVaultAddressesSet();
        if (!ownAddresses.has(params.destinationPubkey)) {
          if (
            !params.passphrase ||
            !(await this._verifyPassphraseRateLimited(params.passphrase))
          ) {
            throw new Error(
              "COLD_VAULT_EXTERNAL_SPEND_REAUTH_REQUIRED: Spending from COLD vault to an external address requires vault passphrase re-authentication"
            );
          }
        }

        const rotPlan = this.vault.prepareColdVaultOtsSpendAndRotate({
          destinationPubkey: params.destinationPubkey,
          spendLamports: BigInt(params.spendLamports),
          currentColdBalanceLamports: BigInt(params.currentColdBalanceLamports),
          txFeeLamports: BigInt(params.txFeeLamports ?? 5000n)
        });
        this.trustedAddresses.add(rotPlan.newQuantumColdVaultPubkey);

        const v0Msg = compileV0MessageFast(
          rotPlan.retiredColdVaultPubkey,
          this.cachedBlockhashB58,
          rotPlan.instructions
        );
        const signed = this.vault.dualSignTransactionBytes(v0Msg, {
          tier: "COLD",
          index: rotPlan.signingColdIndex,
          slot: this.currentSlot
        });
        this.vault.envelope.state.coldKeyExposedOnChain = false;

        return {
          status: "COLD_VAULT_OTS_ROTATED_AND_SIGNED",
          retiredColdVaultPubkey: rotPlan.retiredColdVaultPubkey,
          newQuantumColdVaultPubkey: rotPlan.newQuantumColdVaultPubkey,
          newQuantumColdVaultIndex: rotPlan.newQuantumColdVaultIndex,
          spendLamports: rotPlan.spendLamports.toString(),
          sweepToNextColdLamports: rotPlan.sweepToNextColdLamports.toString(),
          remainingOnExposedVaultLamports: "0",
          signatureBase58: signed.signatureBase58,
          signedTransactionBase64: signed.wireTransaction.toString("base64"),
          quantumProof: signed.quantumProof
        };
      }

      case "qsafe_verifyQuantumProof": {
        const msgBuf = Buffer.from(params.messageBase64, "base64");
        if (this.vault && !params.allowForeignRoot) {
          return this.vault.verifyOwnQuantumProof(params.proof, msgBuf);
        }
        return WotsXmssEngine.verifyTransactionQuantumProof(params.proof, msgBuf, {
          ...(params.pinnedExpectations || {})
        });
      }

      case "qsafe_exportHotKey": {
        this._requireUnlocked();
        if (!params.passphrase || typeof params.passphrase !== "string") {
          throw new Error(
            "PASSPHRASE_REAUTH_REQUIRED: qsafe_exportHotKey requires explicit vault passphrase verification"
          );
        }
        const passValid = await this._verifyPassphraseRateLimited(params.passphrase);
        if (!passValid) {
          throw new Error("PASSPHRASE_REAUTH_FAILED: Invalid vault passphrase for qsafe_exportHotKey");
        }

        const secretKeyBase58 = this.vault.exportHotWalletBase58();
        const summary = this.vault.getPublicVaultSummary();
        return {
          exported: true,
          primaryHotWalletPubkey: summary.primaryHotWallet.pubkey,
          secretKeyBase58
        };
      }

      default:
        throw new Error(`Unsupported RPC method: ${method}`);
    }
  }
}

/**
 * Starts a loopback-only HTTP JSON-RPC 2.0 server wrapping QSafeWalletBridge.
 */
function startWalletHttpServer(options = {}) {
  const bridge = new QSafeWalletBridge(options);
  const host = options.host || "127.0.0.1";
  const isLoopback = host === "127.0.0.1" || host === "localhost" || host === "::1";
  if (!isLoopback && !options.allowNonLoopbackBind) {
    throw new Error(
      `LOOPBACK_BIND_REQUIRED: Refusing to bind wallet server to ${host} without allowNonLoopbackBind=true`
    );
  }
  const port = options.port ?? 0;
  const requireAuthToken = options.requireAuthToken !== false;

  const isTrustedHostHeader = (hostHeader) => {
    if (!hostHeader) return true;
    const h = String(hostHeader).toLowerCase().split(":")[0];
    return h === "127.0.0.1" || h === "localhost" || h === "[::1]";
  };

  const isTrustedOriginHeader = (originHeader) => {
    if (!originHeader) return true;
    const o = String(originHeader);
    if (options.corsOrigin && o === options.corsOrigin) return true;
    try {
      const parsed = new URL(o);
      if (parsed.protocol === "chrome-extension:") {
        return /^[a-p]{32}$/.test(parsed.hostname);
      }
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        return (
          parsed.hostname === "127.0.0.1" ||
          parsed.hostname === "localhost" ||
          parsed.hostname === "[::1]"
        );
      }
      return false;
    } catch (_) {
      return false;
    }
  };

  const verifyBearerTokenConstantTime = (candidate) => {
    if (!candidate || typeof candidate !== "string") return false;
    const a = Buffer.from(candidate, "utf8");
    const b = Buffer.from(bridge.sessionAuthToken, "utf8");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  };

  const server = http.createServer(async (req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Access-Control-Allow-Origin", options.corsOrigin || "http://127.0.0.1");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", `Content-Type, ${AUTH_HEADER_NAME}`);

    if (!isTrustedHostHeader(req.headers.host)) {
      res.writeHead(403);
      res.end(JSON.stringify({ error: "DNS_REBINDING_BLOCKED: Untrusted Host header" }));
      return;
    }

    if (!isTrustedOriginHeader(req.headers.origin)) {
      res.writeHead(403);
      res.end(JSON.stringify({ error: "UNTRUSTED_ORIGIN_BLOCKED: Cross-origin request denied" }));
      return;
    }

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === "GET" && req.url === "/health") {
      const authed =
        !requireAuthToken ||
        verifyBearerTokenConstantTime(req.headers[AUTH_HEADER_LOWER]);
      res.writeHead(200);
      res.end(
        JSON.stringify(
          authed
            ? {
                status: "ok",
                engine: "QSAFE_WALLET_RPC_V1",
                unlocked: Boolean(bridge.vault)
              }
            : { status: "ok" }
        )
      );
      return;
    }

    if (req.method !== "POST") {
      res.writeHead(405);
      res.end(JSON.stringify({ error: "Method Not Allowed" }));
      return;
    }

    const chunks = [];
    let totalBytes = 0;
    let payloadTooLarge = false;
    req.on("data", (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes <= 1024 * 1024) {
        chunks.push(chunk);
      } else {
        payloadTooLarge = true;
      }
    });

    req.on("end", async () => {
      if (payloadTooLarge) {
        res.writeHead(413);
        res.end(JSON.stringify({ error: "Payload Too Large" }));
        return;
      }

      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch (_) {
        res.writeHead(400);
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: { code: -32700, message: "Parse error" }
          })
        );
        return;
      }

      const id = body.id ?? 1;

      if (requireAuthToken) {
        const headerToken = req.headers[AUTH_HEADER_LOWER];
        const bodyToken = body.authToken || (body.params && body.params.authToken);
        const tokenOk =
          verifyBearerTokenConstantTime(headerToken) ||
          verifyBearerTokenConstantTime(bodyToken);

        if (!tokenOk) {
          res.writeHead(401);
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id,
              error: {
                code: -32001,
                message: `UNAUTHORIZED_SESSION_TOKEN: Missing or invalid ${AUTH_HEADER_NAME}`
              }
            })
          );
          return;
        }
      }

      try {
        const result = await bridge.handleRpcMethod(body.method, body.params || {});
        res.writeHead(200);
        res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
      } catch (err) {
        res.writeHead(200);
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id,
            error: {
              code: -32000,
              message: err.message
            }
          })
        );
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(port, host, () => {
      const addr = server.address();
      resolve({
        bridge,
        server,
        authHeader: AUTH_HEADER_NAME,
        authToken: bridge.sessionAuthToken,
        url: `http://${host}:${addr.port}`,
        port: addr.port,
        close: () =>
          new Promise((resClose) => {
            bridge.handleRpcMethod("wallet_lockVault").catch(() => {});
            server.close(() => resClose());
          })
      });
    });
  });
}

if (require.main === module) {
  const port = Number(process.env.QSAFE_PORT || 8788);
  startWalletHttpServer({ port }).then((daemon) => {
    console.log(`[quantum-safe-wallet] JSON-RPC 2.0 server listening on ${daemon.url}`);
    console.log(`[quantum-safe-wallet] Session header ${daemon.authHeader}: ${daemon.authToken}`);
    const shutdown = () => {
      daemon.close().then(() => process.exit(0));
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  });
}

module.exports = {
  QSafeWalletBridge,
  startWalletHttpServer,
  AUTH_HEADER_NAME
};
