"use strict";

/**
 * quantum-safe-wallet - Part 1: Post-Quantum WOTS+/XMSS Key Vault
 * ===============================================================
 * Zero-dependency post-quantum stateful hash-based signature engine (WOTS+ w=16,
 * 64 message chains + 3 Winternitz inverse checksum chains = 67 chains, binary
 * XMSS Merkle authentication trees, monotonic sigSeq OTS state protection),
 * off-curve SHA-256 hash-locked PDA vault derivation, and AES-256-GCM /
 * PBKDF2-HMAC-SHA512 encrypted key storage.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { promisify } = require("util");

const pbkdf2Async = promisify(crypto.pbkdf2);

const SYSTEM_PROGRAM_ID_B58 = "11111111111111111111111111111111";
const MEMO_PROGRAM_ID_B58 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const QSAFE_PQ_VAULT_PROGRAM_ID_B58 = "QSafePQVau1t1111111111111111111111111111111";
const DEFAULT_VAULT_DIR = path.resolve(os.homedir(), ".qsafe-wallet");

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = new Int16Array(256).fill(-1);
for (let i = 0; i < B58_ALPHABET.length; i++) {
  B58_MAP[B58_ALPHABET.charCodeAt(i)] = i;
}

const B58_HEX32_CACHE = new Map();
const B58_DECODE_CACHE = new Map();

function encodeB58(source) {
  const bytes = Buffer.isBuffer(source) ? source : Buffer.from(source);
  if (bytes.length === 0) return "";
  let hexKey = null;
  if (bytes.length === 32) {
    hexKey = bytes.toString("hex");
    const cached = B58_HEX32_CACHE.get(hexKey);
    if (cached !== undefined) return cached;
  }
  const digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    out += "1";
  }
  if (!(digits.length === 1 && digits[0] === 0)) {
    for (let i = digits.length - 1; i >= 0; i--) {
      out += B58_ALPHABET[digits[i]];
    }
  }
  if (hexKey !== null) {
    if (B58_HEX32_CACHE.size > 8192) B58_HEX32_CACHE.clear();
    B58_HEX32_CACHE.set(hexKey, out);
  }
  return out;
}

function decodeB58(str) {
  if (typeof str !== "string" || str.length === 0) return Buffer.alloc(0);
  const cached = B58_DECODE_CACHE.get(str);
  if (cached !== undefined) return Buffer.from(cached);
  const bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    const val = c < 256 ? B58_MAP[c] : -1;
    if (val === -1) throw new Error(`Invalid Base58 character at index ${i}`);
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;
  const out = Buffer.allocUnsafe(zeros + (str.length === zeros ? 0 : bytes.length));
  out.fill(0, 0, zeros);
  if (str.length !== zeros) {
    for (let i = 0; i < bytes.length; i++) {
      out[zeros + i] = bytes[bytes.length - 1 - i];
    }
  }
  if (out.length === 32) {
    B58_HEX32_CACHE.set(out.toString("hex"), str);
    if (B58_DECODE_CACHE.size > 8192) B58_DECODE_CACHE.clear();
    B58_DECODE_CACHE.set(str, out);
  }
  return out;
}

// PKCS#8 ASN.1 DER prefix for a 32-byte Ed25519 private seed (RFC 8410)
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
// SubjectPublicKeyInfo ASN.1 DER prefix for a 32-byte Ed25519 public key (RFC 8410)
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const KDF_ITERATIONS = 600_000;
const KDF_MIN_ITERATIONS = 100_000;
const KDF_MAX_ITERATIONS = 2_000_000;
const KDF_KEYLEN = 32;
const KDF_DIGEST = "sha512";
const CIPHER_ALGO = "aes-256-gcm";
const MIN_PASSPHRASE_LENGTH = 10;
const SIG_SEQ_RESERVE_WINDOW = 1024;
const VAULT_FORMAT_VERSION = "1.2.0";

function assertSaneKdfIterations(iterationsOrEnvelope) {
  const it =
    typeof iterationsOrEnvelope === "number"
      ? iterationsOrEnvelope
      : iterationsOrEnvelope && iterationsOrEnvelope.iterations !== undefined
      ? iterationsOrEnvelope.iterations
      : KDF_ITERATIONS;
  if (!Number.isInteger(it) || it < KDF_MIN_ITERATIONS || it > KDF_MAX_ITERATIONS) {
    throw new Error(
      `VAULT_KDF_PARAMS_OUT_OF_RANGE: iterations must be an integer in [${KDF_MIN_ITERATIONS}, ${KDF_MAX_ITERATIONS}]`
    );
  }
  return it;
}

const FRESH_ENVELOPES = new WeakSet();

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
}

const ALLOWED_VAULT_ROOTS = [
  fs.realpathSync(os.tmpdir()),
  os.tmpdir(),
  DEFAULT_VAULT_DIR
];

function validateSafeVaultFilePath(filePath, allowExistingOverwrite = false) {
  if (!filePath || typeof filePath !== "string") {
    throw new Error("Invalid vaultFilePath");
  }
  if (filePath.includes("\0")) {
    throw new Error("Null byte in vaultFilePath disallowed");
  }
  const resolved = path.resolve(filePath);
  const preCheckAllowed = ALLOWED_VAULT_ROOTS.some(
    (root) => resolved === root || resolved.startsWith(root + path.sep)
  );
  if (!preCheckAllowed) {
    throw new Error(
      `SECURITY_PATH_TRAVERSAL_BLOCKED: Vault file ${resolved} must reside inside ~/.qsafe-wallet or system tmpdir`
    );
  }

  const parentDir = path.dirname(resolved);
  fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
  const realParent = fs.realpathSync(parentDir);
  const fullCanonical = path.join(realParent, path.basename(resolved));

  const isInsideAllowed = ALLOWED_VAULT_ROOTS.some(
    (root) => fullCanonical === root || fullCanonical.startsWith(root + path.sep)
  );
  if (!isInsideAllowed) {
    throw new Error(
      `SECURITY_PATH_TRAVERSAL_BLOCKED: Vault file ${fullCanonical} must reside inside ~/.qsafe-wallet or system tmpdir`
    );
  }

  if (fs.existsSync(fullCanonical)) {
    const st = fs.lstatSync(fullCanonical);
    if (st.isSymbolicLink()) {
      throw new Error("SECURITY_SYMLINK_BLOCKED: Refusing to read/write vault through symlink");
    }
    if (!allowExistingOverwrite) {
      throw new Error(
        "VAULT_FILE_ALREADY_EXISTS: Refusing to overwrite existing vault without explicit allowOverwrite=true"
      );
    }
  }
  return fullCanonical;
}

function zeroizeBuffer(buf) {
  if (!buf) return;
  try {
    if (typeof buf.fill === "function") {
      buf.fill(0);
    }
  } catch (_) {}
}

function deriveEd25519PublicKeyFromSeed32(seed32) {
  if (!Buffer.isBuffer(seed32) || seed32.length !== 32) {
    throw new Error("Invalid Ed25519 seed length: expected 32 bytes");
  }
  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seed32]);
  try {
    const privKeyObj = crypto.createPrivateKey({
      key: pkcs8Der,
      format: "der",
      type: "pkcs8"
    });
    const pubKeyObj = crypto.createPublicKey(privKeyObj);
    const spkiDer = pubKeyObj.export({ format: "der", type: "spki" });
    return Buffer.from(spkiDer.subarray(spkiDer.length - 32));
  } finally {
    zeroizeBuffer(pkcs8Der);
  }
}

function signEd25519Seed32Native(seed32, messageBuf) {
  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seed32]);
  try {
    const privKeyObj = crypto.createPrivateKey({
      key: pkcs8Der,
      format: "der",
      type: "pkcs8"
    });
    return crypto.sign(null, messageBuf, privKeyObj);
  } finally {
    zeroizeBuffer(pkcs8Der);
  }
}

function verifyEd25519Native(pubkey32, messageBuf, signature64) {
  const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, pubkey32]);
  const pubKeyObj = crypto.createPublicKey({
    key: spkiDer,
    format: "der",
    type: "spki"
  });
  return crypto.verify(null, messageBuf, pubKeyObj, signature64);
}

function deriveDomainChildSeed32(masterSeed32, domainTag, index) {
  const idxBuf = Buffer.allocUnsafe(4);
  idxBuf.writeUInt32LE(index >>> 0, 0);
  const hmac = crypto.createHmac("sha512", masterSeed32);
  hmac.update("QSAFE_HD_KEY_TREE_V1:");
  hmac.update(domainTag);
  hmac.update(":");
  hmac.update(idxBuf);
  const digest64 = hmac.digest();
  const childSeed32 = Buffer.from(digest64.subarray(0, 32));
  zeroizeBuffer(digest64);
  return childSeed32;
}

/**
 * Derives an off-curve SHA-256 hash-locked Program-Derived Address (PDA) vault.
 * Because a PDA is locked to a SHA-256 hash commitment and has no Ed25519 private key,
 * Shor's elliptic-curve discrete-log algorithm cannot derive a private key from this address.
 */
function deriveHashLockedQuantumPdaVault(xmssMasterRootHex, coldIndex = 0) {
  const progBuf = decodeB58(QSAFE_PQ_VAULT_PROGRAM_ID_B58);
  const rootBuf = Buffer.from(xmssMasterRootHex, "hex");
  const idxBuf = Buffer.allocUnsafe(4);
  idxBuf.writeUInt32LE(coldIndex >>> 0, 0);

  const pdaHash = crypto
    .createHash("sha256")
    .update("QSAFE_PQ_PDA_VAULT_V1")
    .update(rootBuf)
    .update(idxBuf)
    .update(Buffer.from([255]))
    .update(progBuf)
    .update("ProgramDerivedAddress")
    .digest();

  return {
    pdaAddressB58: encodeB58(pdaHash),
    programIdB58: QSAFE_PQ_VAULT_PROGRAM_ID_B58,
    commitmentRootHex: xmssMasterRootHex,
    coldIndex,
    quantumSecurityModel: "HASH_LOCKED_PDA_NO_ED25519_PRIVATE_KEY"
  };
}

// ============================================================================
// STATEFUL POST-QUANTUM WOTS+ (w=16, 67 CHAINS) & XMSS MERKLE TREE ENGINE
// ============================================================================

const sha256Fast =
  typeof crypto.hash === "function"
    ? (buf) => crypto.hash("sha256", buf, "buffer")
    : (buf) => crypto.createHash("sha256").update(buf).digest();

const WOTS_MSG_CHAINS = 64; // 64 nibbles = full 256-bit SHA-256 message binding (w=16)
const WOTS_CSUM_CHAINS = 3; // max inverse checksum 64 * 15 = 960 (0x3C0), fits in 3 nibbles
const WOTS_TOTAL_CHAINS = WOTS_MSG_CHAINS + WOTS_CSUM_CHAINS; // 67 chains * 32B = 2,144 bytes
const DEFAULT_XMSS_SUBTREE_HEIGHT = 4; // 16 OTS leaves per XMSS binary Merkle subtree

function hashMerklePair(left32, right32) {
  const buf = Buffer.allocUnsafe(65);
  buf[0] = 0x01;
  left32.copy(buf, 1, 0, 32);
  right32.copy(buf, 33, 0, 32);
  return sha256Fast(buf);
}

class WotsXmssEngine {
  /**
   * @param {Buffer} xmssMasterSeed32 - 32-byte post-quantum master seed
   * @param {number} [initialSigSeq=0] - Initial monotonic one-time signature counter
   * @param {object} [opts]
   * @param {number} [opts.subtreeHeight=4] - Height H of each binary XMSS Merkle subtree (2^H leaves)
   */
  constructor(xmssMasterSeed32, initialSigSeq = 0, opts = {}) {
    if (!Buffer.isBuffer(xmssMasterSeed32) || xmssMasterSeed32.length !== 32) {
      throw new Error("WotsXmssEngine requires a 32-byte Buffer seed");
    }
    this.subtreeHeight = opts.subtreeHeight ?? DEFAULT_XMSS_SUBTREE_HEIGHT;
    if (!Number.isInteger(this.subtreeHeight) || this.subtreeHeight < 2 || this.subtreeHeight > 8) {
      throw new Error("Invalid XMSS subtreeHeight: must be an integer in [2, 8]");
    }
    this.leavesPerSubtree = 1 << this.subtreeHeight;

    this._mask = crypto.randomBytes(32);
    this._maskedSeed = Buffer.allocUnsafe(32);
    for (let i = 0; i < 32; i++) {
      this._maskedSeed[i] = xmssMasterSeed32[i] ^ this._mask[i];
    }

    this.sigSeqCounter = Number(initialSigSeq) || 0;
    this.subtreeCache = new Map(); // subtreeEpoch -> { epoch, leaves, layers, rootBuf, rootHex }

    const initialSubtree = this.getOrBuildXmssSubtree(
      Math.floor(this.sigSeqCounter / this.leavesPerSubtree)
    );
    this.masterRootBuf = initialSubtree.rootBuf;
    this.masterRootHex = initialSubtree.rootHex;
  }

  _withUnmaskedSeed(fn) {
    const tempSeed = Buffer.allocUnsafe(32);
    for (let i = 0; i < 32; i++) {
      tempSeed[i] = this._maskedSeed[i] ^ this._mask[i];
    }
    try {
      return fn(tempSeed);
    } finally {
      zeroizeBuffer(tempSeed);
    }
  }

  deriveLeafPreimage(leafIndex) {
    return this._withUnmaskedSeed((seed) =>
      crypto
        .createHash("sha256")
        .update(`QSAFE_OTS_PREIMAGE_V1:${leafIndex}:`)
        .update(seed)
        .digest()
    );
  }

  _deriveWotsSecretChains(leafIndex) {
    return this._withUnmaskedSeed((seed) => {
      const prefix = Buffer.from(`QSAFE_WOTS_SK_V1:${leafIndex}:`, "utf8");
      const chains = new Array(WOTS_TOTAL_CHAINS);
      const buf1 = Buffer.allocUnsafe(prefix.length + 2 + 32);
      prefix.copy(buf1, 0);
      buf1[prefix.length + 1] = 0x3a;
      seed.copy(buf1, prefix.length + 2);

      const buf2 = Buffer.allocUnsafe(prefix.length + 3 + 32);
      prefix.copy(buf2, 0);
      buf2[prefix.length + 2] = 0x3a;
      seed.copy(buf2, prefix.length + 3);

      try {
        for (let c = 0; c < WOTS_TOTAL_CHAINS; c++) {
          if (c < 10) {
            buf1[prefix.length] = 0x30 + c;
            chains[c] = sha256Fast(buf1);
          } else {
            buf2[prefix.length] = 0x30 + ((c / 10) | 0);
            buf2[prefix.length + 1] = 0x30 + (c % 10);
            chains[c] = sha256Fast(buf2);
          }
        }
        return chains;
      } finally {
        zeroizeBuffer(buf1);
        zeroizeBuffer(buf2);
      }
    });
  }

  /**
   * Computes the 67 WOTS+ (w=16) step indices [0..15] for a 32-byte message digest:
   * - Chains 0..63: 64 message nibbles covering all 256 bits of the domain-bound digest
   * - Chains 64..66: 3 Winternitz inverse checksum nibbles (sum(15 - d_i) in [0..960])
   *   so advancing any message hash step strictly decreases the checksum, blocking
   *   forward-hash forgery without inverting SHA-256.
   */
  static computeWotsStepsWithChecksum(txDigest32) {
    const boundDigest = crypto
      .createHash("sha256")
      .update("QSAFE_WOTS_MSG_BIND_V1:")
      .update(txDigest32)
      .digest();
    const steps = new Uint8Array(WOTS_TOTAL_CHAINS);
    let csum = 0;
    for (let i = 0; i < 32; i++) {
      const hi = boundDigest[i] >>> 4;
      const lo = boundDigest[i] & 0x0f;
      steps[2 * i] = hi;
      steps[2 * i + 1] = lo;
      csum += 15 - hi + (15 - lo);
    }
    steps[WOTS_MSG_CHAINS] = (csum >>> 8) & 0x0f;
    steps[WOTS_MSG_CHAINS + 1] = (csum >>> 4) & 0x0f;
    steps[WOTS_MSG_CHAINS + 2] = csum & 0x0f;
    return steps;
  }

  static stepWotsChain(val32, leafIndex, chainIdx, startStep, steps) {
    if (steps <= 0) return Buffer.from(val32);
    const scratch = Buffer.allocUnsafe(38);
    val32.copy(scratch, 0, 0, 32);
    scratch[32] = chainIdx & 0xff;
    scratch.writeUInt32LE(leafIndex >>> 0, 34);
    let cur = null;
    for (let s = 0; s < steps; s++) {
      scratch[33] = (startStep + s) & 0xff;
      cur = sha256Fast(scratch);
      if (s + 1 < steps) {
        cur.copy(scratch, 0, 0, 32);
      }
    }
    return cur;
  }

  static walkWotsChainCapture(val32, leafIndex, chainIdx, captureAt) {
    const scratch = Buffer.allocUnsafe(38);
    val32.copy(scratch, 0, 0, 32);
    scratch[32] = chainIdx & 0xff;
    scratch.writeUInt32LE(leafIndex >>> 0, 34);
    let captured = captureAt === 0 ? Buffer.from(val32) : null;
    let cur = null;
    for (let s = 0; s < 15; s++) {
      scratch[33] = s & 0xff;
      cur = sha256Fast(scratch);
      if (s + 1 === captureAt) captured = Buffer.from(cur);
      if (s + 1 < 15) cur.copy(scratch, 0, 0, 32);
    }
    return { tip: cur, captured };
  }

  _computeWotsPublicLeaf(leafIndex, captureSteps = null) {
    const secretChains = this._deriveWotsSecretChains(leafIndex);
    const lTreeHasher = crypto.createHash("sha256");
    lTreeHasher.update(`QSAFE_XMSS_LTREE_V1:${leafIndex}:`);
    let capturedElements = null;
    try {
      if (captureSteps) capturedElements = new Array(WOTS_TOTAL_CHAINS);
      for (let c = 0; c < WOTS_TOTAL_CHAINS; c++) {
        if (captureSteps) {
          const walk = WotsXmssEngine.walkWotsChainCapture(
            secretChains[c],
            leafIndex,
            c,
            captureSteps[c]
          );
          capturedElements[c] = walk.captured;
          lTreeHasher.update(walk.tip);
        } else {
          const tip = WotsXmssEngine.stepWotsChain(secretChains[c], leafIndex, c, 0, 15);
          lTreeHasher.update(tip);
        }
      }
    } finally {
      for (let c = 0; c < WOTS_TOTAL_CHAINS; c++) zeroizeBuffer(secretChains[c]);
    }
    return {
      wotsPublicRootBuf: lTreeHasher.digest(),
      capturedElements
    };
  }

  /**
   * Builds and caches the binary XMSS Merkle tree for `subtreeEpoch`.
   * Each leaf k in [0 .. 2^H - 1] commits to the 67-chain WOTS+ L-tree root of global leaf
   * `epoch * 2^H + k`.
   */
  getOrBuildXmssSubtree(subtreeEpoch) {
    const existing = this.subtreeCache.get(subtreeEpoch);
    if (existing) return existing;

    const baseLeafIndex = subtreeEpoch * this.leavesPerSubtree;
    const leaves = new Array(this.leavesPerSubtree);
    for (let i = 0; i < this.leavesPerSubtree; i++) {
      leaves[i] = this._computeWotsPublicLeaf(baseLeafIndex + i).wotsPublicRootBuf;
    }

    const layers = [leaves];
    let currentLayer = leaves;
    while (currentLayer.length > 1) {
      const nextLayer = new Array(currentLayer.length >> 1);
      for (let i = 0; i < nextLayer.length; i++) {
        nextLayer[i] = hashMerklePair(currentLayer[2 * i], currentLayer[2 * i + 1]);
      }
      layers.push(nextLayer);
      currentLayer = nextLayer;
    }

    const rootBuf = currentLayer[0];
    const subtree = {
      epoch: subtreeEpoch,
      height: this.subtreeHeight,
      leaves,
      layers,
      rootBuf,
      rootHex: rootBuf.toString("hex")
    };

    if (this.subtreeCache.size > 64) {
      this.subtreeCache.clear();
    }
    this.subtreeCache.set(subtreeEpoch, subtree);
    return subtree;
  }

  _extractMerkleAuthPathHex(subtree, localLeafIdx) {
    const authPathHex = [];
    let idx = localLeafIdx;
    for (let level = 0; level < subtree.height; level++) {
      const siblingIdx = idx ^ 1;
      authPathHex.push(subtree.layers[level][siblingIdx].toString("hex"));
      idx >>= 1;
    }
    return authPathHex;
  }

  /**
   * Signs `txMessageBytes` using the next strictly monotonic one-time leaf `sigSeq`,
   * producing a 67-chain WOTS+ signature (2,144 bytes) + binary XMSS Merkle authentication path.
   */
  signTransactionQuantumProof(slot, txMessageBytes) {
    const t0 = process.hrtime.bigint();
    const leafIndex = this.sigSeqCounter++;
    const subtreeEpoch = Math.floor(leafIndex / this.leavesPerSubtree);
    const localLeafIndex = leafIndex % this.leavesPerSubtree;

    const txDigest = crypto.createHash("sha256").update(txMessageBytes).digest();
    const steps = WotsXmssEngine.computeWotsStepsWithChecksum(txDigest);

    const subtree = this.getOrBuildXmssSubtree(subtreeEpoch);
    const { wotsPublicRootBuf, capturedElements } = this._computeWotsPublicLeaf(leafIndex, steps);
    const merkleAuthPathHex = this._extractMerkleAuthPathHex(subtree, localLeafIndex);

    const preimageBuf = this.deriveLeafPreimage(leafIndex);
    const otpkBuf = sha256Fast(preimageBuf);

    const signLatencyUs = Number(process.hrtime.bigint() - t0) / 1e3;

    const proof = {
      scheme: "QSAFE_WOTS_PLUS_XMSS_SHA256_W16_C67",
      slot: Number(slot) || 0,
      sigSeq: leafIndex,
      subtreeEpoch,
      localLeafIndex,
      subtreeHeight: this.subtreeHeight,
      masterRootHex: this.masterRootHex,
      xmssSubtreeRootHex: subtree.rootHex,
      txDigestHex: txDigest.toString("hex"),
      finalizeOtpkHex: otpkBuf.toString("hex"),
      revealedPreimageHex: preimageBuf.toString("hex"),
      wotsPublicRootHex: wotsPublicRootBuf.toString("hex"),
      wotsChainElementsHex: capturedElements.map((b) => b.toString("hex")),
      merkleAuthPathHex,
      preimageWireBytes: 32,
      wotsWireBytes: WOTS_TOTAL_CHAINS * 32,
      merklePathBytes: merkleAuthPathHex.length * 32,
      signLatencyUs: Number(signLatencyUs.toFixed(2))
    };

    zeroizeBuffer(preimageBuf);
    return proof;
  }

  /**
   * Verifies a 67-chain WOTS+ signature + XMSS binary Merkle authentication path against
   * `txMessageBytes` and optional `pinnedExpectations` (`expectedMasterRootHex`,
   * `expectedXmssRootHex`, `minAcceptedSigSeq`).
   */
  static verifyTransactionQuantumProof(proof, txMessageBytes, pinnedExpectations = {}) {
    if (
      !proof ||
      !Array.isArray(proof.wotsChainElementsHex) ||
      proof.wotsChainElementsHex.length !== WOTS_TOTAL_CHAINS ||
      !Array.isArray(proof.merkleAuthPathHex) ||
      !Number.isInteger(proof.sigSeq) ||
      proof.sigSeq < 0
    ) {
      return { verified: false, preimageValid: false, wotsValid: false, merkleValid: false, reason: "MALFORMED_PROOF" };
    }

    if (
      pinnedExpectations.minAcceptedSigSeq !== undefined &&
      proof.sigSeq < pinnedExpectations.minAcceptedSigSeq
    ) {
      return {
        verified: false,
        preimageValid: false,
        wotsValid: false,
        merkleValid: false,
        reason: "OTS_SIGSEQ_REPLAY_REJECTED"
      };
    }

    if (
      pinnedExpectations.expectedMasterRootHex &&
      proof.masterRootHex !== pinnedExpectations.expectedMasterRootHex
    ) {
      return {
        verified: false,
        preimageValid: false,
        wotsValid: false,
        merkleValid: false,
        reason: "PINNED_MASTER_ROOT_MISMATCH"
      };
    }

    const expectedTreeRoot =
      pinnedExpectations.expectedXmssRootHex ||
      (proof.subtreeEpoch === 0 && pinnedExpectations.expectedMasterRootHex
        ? pinnedExpectations.expectedMasterRootHex
        : proof.xmssSubtreeRootHex);

    if (
      pinnedExpectations.expectedXmssRootHex &&
      proof.xmssSubtreeRootHex !== pinnedExpectations.expectedXmssRootHex
    ) {
      return {
        verified: false,
        preimageValid: false,
        wotsValid: false,
        merkleValid: false,
        reason: "PINNED_XMSS_ROOT_MISMATCH"
      };
    }

    if (
      pinnedExpectations.expectedFinalizeOtpkHex &&
      proof.finalizeOtpkHex !== pinnedExpectations.expectedFinalizeOtpkHex
    ) {
      return {
        verified: false,
        preimageValid: false,
        wotsValid: false,
        merkleValid: false,
        reason: "PINNED_OTPK_MISMATCH"
      };
    }

    const t0 = process.hrtime.bigint();

    // 1. Verify 32-byte one-time preimage reveal: SHA256(preimage) == finalizeOtpk
    const preimageBuf = Buffer.from(String(proof.revealedPreimageHex || ""), "hex");
    const computedOtpkHex = preimageBuf.length === 32 ? sha256Fast(preimageBuf).toString("hex") : "";
    const expectedOtpk = pinnedExpectations.expectedFinalizeOtpkHex || proof.finalizeOtpkHex;
    const preimageValid = preimageBuf.length === 32 && computedOtpkHex === expectedOtpk;

    // 2. Reconstruct all 67 WOTS+ chain tips (64 message chains + 3 inverse checksum chains)
    const txDigest = crypto.createHash("sha256").update(txMessageBytes).digest();
    const steps = WotsXmssEngine.computeWotsStepsWithChecksum(txDigest);

    const lTreeHasher = crypto.createHash("sha256");
    lTreeHasher.update(`QSAFE_XMSS_LTREE_V1:${proof.sigSeq}:`);
    for (let c = 0; c < WOTS_TOTAL_CHAINS; c++) {
      const stepVal = steps[c];
      const elemBuf = Buffer.from(String(proof.wotsChainElementsHex[c] || ""), "hex");
      if (elemBuf.length !== 32) {
        return {
          verified: false,
          preimageValid,
          wotsValid: false,
          merkleValid: false,
          reason: "INVALID_CHAIN_LEN"
        };
      }
      const remainingSteps = 15 - stepVal;
      const chainTip = WotsXmssEngine.stepWotsChain(
        elemBuf,
        proof.sigSeq,
        c,
        stepVal,
        remainingSteps
      );
      lTreeHasher.update(chainTip);
    }

    const reconstructedLeafBuf = lTreeHasher.digest();
    const reconstructedLeafHex = reconstructedLeafBuf.toString("hex");
    const wotsValid =
      reconstructedLeafHex === proof.wotsPublicRootHex &&
      txDigest.toString("hex") === proof.txDigestHex;

    // 3. Walk the binary XMSS Merkle authentication path from reconstructed leaf to tree root
    let curNode = reconstructedLeafBuf;
    let idx = Number(proof.localLeafIndex);
    const height = Number(proof.subtreeHeight);
    let merkleValid =
      Number.isInteger(idx) &&
      Number.isInteger(height) &&
      height === proof.merkleAuthPathHex.length &&
      idx >= 0 &&
      idx < 1 << height;

    if (merkleValid) {
      for (let level = 0; level < height; level++) {
        const siblingBuf = Buffer.from(String(proof.merkleAuthPathHex[level] || ""), "hex");
        if (siblingBuf.length !== 32) {
          merkleValid = false;
          break;
        }
        curNode = (idx & 1) === 0 ? hashMerklePair(curNode, siblingBuf) : hashMerklePair(siblingBuf, curNode);
        idx >>= 1;
      }
      if (merkleValid) {
        merkleValid = curNode.toString("hex") === expectedTreeRoot;
      }
    }

    const verifyLatencyUs = Number(process.hrtime.bigint() - t0) / 1e3;
    const isRootPinned = Boolean(
      pinnedExpectations.expectedXmssRootHex ||
        (proof.subtreeEpoch === 0 && pinnedExpectations.expectedMasterRootHex)
    );

    return {
      verified: preimageValid && wotsValid && merkleValid,
      preimageValid,
      wotsValid,
      merkleValid,
      authenticity: isRootPinned
        ? "PINNED_XMSS_MERKLE_ROOT"
        : "SELF_CONSISTENT_UNPINNED",
      verifyLatencyUs: Number(verifyLatencyUs.toFixed(2)),
      reason:
        preimageValid && wotsValid && merkleValid
          ? null
          : !wotsValid
          ? "WOTS_CHAIN_OR_DIGEST_MISMATCH"
          : !merkleValid
          ? "XMSS_MERKLE_PATH_MISMATCH"
          : "PREIMAGE_MISMATCH"
    };
  }

  destroy() {
    zeroizeBuffer(this._maskedSeed);
    zeroizeBuffer(this._mask);
    this.subtreeCache.clear();
  }
}

// ============================================================================
// ENCRYPTED POST-QUANTUM VAULT ENGINE (PBKDF2-SHA512 + AES-256-GCM + TIERS)
// ============================================================================

class VaultCryptoEngine {
  static _validatePassphrase(passphrase) {
    if (
      !passphrase ||
      typeof passphrase !== "string" ||
      passphrase.length < MIN_PASSPHRASE_LENGTH
    ) {
      throw new Error(
        `RULE_11_WEAK_PASSPHRASE: Vault passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`
      );
    }
  }

  static _parseImportedHotSeed(importedHotSecretKey) {
    if (!importedHotSecretKey) return null;
    const raw =
      typeof importedHotSecretKey === "string"
        ? Buffer.from(decodeB58(importedHotSecretKey))
        : Buffer.from(importedHotSecretKey);
    try {
      if (raw.length === 64) return Buffer.from(raw.subarray(0, 32));
      if (raw.length === 32) return Buffer.from(raw);
      throw new Error("Imported hot secret key must be 32 or 64 bytes");
    } finally {
      zeroizeBuffer(raw);
    }
  }

  static _buildEnvelopeFromSeeds(masterSeed32, importedHotSeed32, salt, iv, aesKey, iterations) {
    const cold0Seed = deriveDomainChildSeed32(masterSeed32, "COLD_VAULT", 0);
    const cold0Pub = deriveEd25519PublicKeyFromSeed32(cold0Seed);
    zeroizeBuffer(cold0Seed);

    const hot0Seed = importedHotSeed32
      ? Buffer.from(importedHotSeed32)
      : deriveDomainChildSeed32(masterSeed32, "QSAFE_HOT", 0);
    const hot0Pub = deriveEd25519PublicKeyFromSeed32(hot0Seed);
    zeroizeBuffer(hot0Seed);

    const burner0Seed = deriveDomainChildSeed32(masterSeed32, "EPHEMERAL_BURNER", 0);
    const burner0Pub = deriveEd25519PublicKeyFromSeed32(burner0Seed);
    zeroizeBuffer(burner0Seed);

    const guardAnchor0Seed = deriveDomainChildSeed32(masterSeed32, "BALANCE_GUARD_ANCHOR", 0);
    const guardAnchor0Pub = deriveEd25519PublicKeyFromSeed32(guardAnchor0Seed);
    zeroizeBuffer(guardAnchor0Seed);

    const xmssSeed = deriveDomainChildSeed32(masterSeed32, "XMSS_MASTER", 0);
    const xmssEngine = new WotsXmssEngine(xmssSeed, 0);
    const xmssMasterRootHex = xmssEngine.masterRootHex;
    xmssEngine.destroy();
    zeroizeBuffer(xmssSeed);

    const hashLockedPda = deriveHashLockedQuantumPdaVault(xmssMasterRootHex, 0);

    const secretPayload = Buffer.alloc(65, 0);
    secretPayload[0] = importedHotSeed32 ? 1 : 0;
    masterSeed32.copy(secretPayload, 1);
    if (importedHotSeed32) {
      importedHotSeed32.copy(secretPayload, 33);
    }

    let ciphertext;
    let authTag;
    try {
      const cipher = crypto.createCipheriv(CIPHER_ALGO, aesKey, iv);
      ciphertext = Buffer.concat([cipher.update(secretPayload), cipher.final()]);
      authTag = cipher.getAuthTag();
    } finally {
      zeroizeBuffer(secretPayload);
    }

    const freshEnvelope = {
      version: VAULT_FORMAT_VERSION,
      engine: "QSAFE_WOTS_XMSS_VAULT_V1",
      cipher: CIPHER_ALGO,
      kdf: "pbkdf2-sha512",
      iterations,
      saltHex: salt.toString("hex"),
      ivHex: iv.toString("hex"),
      authTagHex: authTag.toString("hex"),
      ciphertextHex: ciphertext.toString("hex"),
      state: {
        activeColdIndex: 0,
        coldKeyExposedOnChain: false,
        coldRotationHistory: [],
        activeBurnerIndex: 0,
        burnerCount: 1,
        hasImportedHotKey: Boolean(importedHotSeed32),
        xmssMasterRootHex,
        quantumColdVaultPubkey: encodeB58(cold0Pub),
        quantumHashLockedPdaVault: hashLockedPda.pdaAddressB58,
        primaryHotWalletPubkey: encodeB58(hot0Pub),
        balanceFloorGuardAnchorPubkey: encodeB58(guardAnchor0Pub),
        xmssSigSeqCounter: 0,
        activeBurnerPubkey: encodeB58(burner0Pub),
        ephemeralBurners: [
          { index: 0, pubkey: encodeB58(burner0Pub), label: "Burner #0" }
        ],
        createdAt: new Date().toISOString()
      }
    };
    FRESH_ENVELOPES.add(freshEnvelope);
    return freshEnvelope;
  }

  static createNewVault(passphrase, options = {}) {
    VaultCryptoEngine._validatePassphrase(passphrase);
    const safePath = options.vaultFilePath
      ? validateSafeVaultFilePath(options.vaultFilePath, Boolean(options.allowOverwrite))
      : null;
    const iterations = assertSaneKdfIterations(options.kdfIterations ?? KDF_ITERATIONS);

    const masterSeed32 = options.masterSeed32
      ? Buffer.from(options.masterSeed32)
      : crypto.randomBytes(32);
    const importedHotSeed32 = VaultCryptoEngine._parseImportedHotSeed(options.importedHotSecretKey);

    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const aesKey = crypto.pbkdf2Sync(passphrase, salt, iterations, KDF_KEYLEN, KDF_DIGEST);

    try {
      const envelope = VaultCryptoEngine._buildEnvelopeFromSeeds(
        masterSeed32,
        importedHotSeed32,
        salt,
        iv,
        aesKey,
        iterations
      );
      const instance = new VaultCryptoEngine(envelope, passphrase, safePath, aesKey);
      if (safePath) {
        instance.persistToDisk(true);
      }
      return instance;
    } finally {
      zeroizeBuffer(masterSeed32);
      zeroizeBuffer(importedHotSeed32);
      zeroizeBuffer(aesKey);
    }
  }

  static async createNewVaultAsync(passphrase, options = {}) {
    VaultCryptoEngine._validatePassphrase(passphrase);
    const safePath = options.vaultFilePath
      ? validateSafeVaultFilePath(options.vaultFilePath, Boolean(options.allowOverwrite))
      : null;
    const iterations = assertSaneKdfIterations(options.kdfIterations ?? KDF_ITERATIONS);

    const masterSeed32 = options.masterSeed32
      ? Buffer.from(options.masterSeed32)
      : crypto.randomBytes(32);
    const importedHotSeed32 = VaultCryptoEngine._parseImportedHotSeed(options.importedHotSecretKey);

    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const aesKey = await pbkdf2Async(passphrase, salt, iterations, KDF_KEYLEN, KDF_DIGEST);

    try {
      const envelope = VaultCryptoEngine._buildEnvelopeFromSeeds(
        masterSeed32,
        importedHotSeed32,
        salt,
        iv,
        aesKey,
        iterations
      );
      const instance = new VaultCryptoEngine(envelope, passphrase, safePath, aesKey);
      if (safePath) {
        instance.persistToDisk(true);
      }
      return instance;
    } finally {
      zeroizeBuffer(masterSeed32);
      zeroizeBuffer(importedHotSeed32);
      zeroizeBuffer(aesKey);
    }
  }

  static loadVault(envelopeOrPath, passphrase) {
    VaultCryptoEngine._validatePassphrase(passphrase);
    let envelope = envelopeOrPath;
    let filePath = null;
    if (typeof envelopeOrPath === "string") {
      filePath = validateSafeVaultFilePath(envelopeOrPath, true);
      envelope = JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
    const engine = new VaultCryptoEngine(envelope, passphrase, filePath);
    engine._withDecryptedSeeds((masterSeed32) => {
      if (masterSeed32.length !== 32) throw new Error("Corrupt vault seed");
    });
    return engine;
  }

  static async loadVaultAsync(envelopeOrPath, passphrase) {
    VaultCryptoEngine._validatePassphrase(passphrase);
    let envelope = envelopeOrPath;
    let filePath = null;
    if (typeof envelopeOrPath === "string") {
      filePath = validateSafeVaultFilePath(envelopeOrPath, true);
      envelope = JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
    const salt = Buffer.from(envelope.saltHex, "hex");
    const kdfIterations = assertSaneKdfIterations(envelope);
    const aesKey = await pbkdf2Async(passphrase, salt, kdfIterations, KDF_KEYLEN, KDF_DIGEST);
    try {
      const engine = new VaultCryptoEngine(envelope, passphrase, filePath, aesKey);
      engine._withDecryptedSeeds((masterSeed32) => {
        if (masterSeed32.length !== 32) throw new Error("Corrupt vault seed");
      });
      return engine;
    } finally {
      zeroizeBuffer(aesKey);
    }
  }

  constructor(envelope, passphrase, vaultFilePath = null, preDerivedAesKey = null) {
    this.envelope = envelope;
    this.vaultFilePath = vaultFilePath;

    const salt = Buffer.from(envelope.saltHex, "hex");
    const derivedAesKey = preDerivedAesKey
      ? Buffer.from(preDerivedAesKey)
      : crypto.pbkdf2Sync(
          passphrase,
          salt,
          assertSaneKdfIterations(envelope),
          KDF_KEYLEN,
          KDF_DIGEST
        );
    this._keyMask = crypto.randomBytes(32);
    this._maskedAesKey = Buffer.allocUnsafe(32);
    for (let i = 0; i < 32; i++) {
      this._maskedAesKey[i] = derivedAesKey[i] ^ this._keyMask[i];
    }
    zeroizeBuffer(derivedAesKey);

    this._authenticateEnvelopeState();

    this.xmssEngine = this._withDecryptedSeeds((masterSeed32) => {
      const xmssSeed = deriveDomainChildSeed32(masterSeed32, "XMSS_MASTER", 0);
      try {
        return new WotsXmssEngine(
          xmssSeed,
          (envelope.state && envelope.state.xmssSigSeqCounter) || 0
        );
      } finally {
        zeroizeBuffer(xmssSeed);
      }
    });

    this._verifyStatePublicKeysAgainstSeed();
  }

  _computeStateMacHex() {
    const aesKey = Buffer.allocUnsafe(32);
    for (let i = 0; i < 32; i++) aesKey[i] = this._maskedAesKey[i] ^ this._keyMask[i];
    try {
      const macKey = crypto.createHmac("sha256", aesKey).update("QSAFE_VAULT_STATE_MAC_V1").digest();
      try {
        const e = this.envelope;
        return crypto
          .createHmac("sha256", macKey)
          .update(
            canonicalJson({
              engine: e.engine,
              cipher: e.cipher,
              kdf: e.kdf,
              iterations: e.iterations || KDF_ITERATIONS,
              saltHex: e.saltHex,
              ivHex: e.ivHex,
              authTagHex: e.authTagHex,
              ciphertextHex: e.ciphertextHex,
              state: e.state
            })
          )
          .digest("hex");
      } finally {
        zeroizeBuffer(macKey);
      }
    } finally {
      zeroizeBuffer(aesKey);
    }
  }

  _authenticateEnvelopeState() {
    const envelope = this.envelope;
    const desc = Object.getOwnPropertyDescriptor(envelope, "stateMacHex");
    if (desc && !desc.get) {
      const stored = Buffer.from(String(desc.value || ""), "hex");
      const expected = Buffer.from(this._computeStateMacHex(), "hex");
      if (stored.length !== expected.length || !crypto.timingSafeEqual(stored, expected)) {
        throw new Error("VAULT_STATE_TAMPERED: state integrity MAC mismatch (vault file was modified)");
      }
    } else if (!desc && !FRESH_ENVELOPES.has(envelope)) {
      throw new Error("VAULT_STATE_TAMPERED: sealed vault is missing its state integrity MAC");
    }
    envelope.version = VAULT_FORMAT_VERSION;
    const self = this;
    Object.defineProperty(envelope, "stateMacHex", {
      enumerable: true,
      configurable: true,
      get() {
        return self._computeStateMacHex();
      }
    });
  }

  _verifyStatePublicKeysAgainstSeed() {
    const st = this.envelope.state;
    const fail = (field) => {
      throw new Error(`VAULT_STATE_TAMPERED: ${field} does not match the encrypted seed`);
    };
    if (!st || typeof st !== "object") fail("state");
    this._withDecryptedSeeds((master, imported) => {
      const pubOf = (domain, idx) => {
        const s = deriveDomainChildSeed32(master, domain, idx);
        try {
          return encodeB58(deriveEd25519PublicKeyFromSeed32(s));
        } finally {
          zeroizeBuffer(s);
        }
      };
      const isIdx = (n) => Number.isInteger(n) && n >= 0 && n < 0xffffffff;
      const epoch0RootHex = this.xmssEngine.getOrBuildXmssSubtree(0).rootHex;
      if (epoch0RootHex !== st.xmssMasterRootHex) fail("xmssMasterRootHex");
      if (!isIdx(st.activeColdIndex)) fail("activeColdIndex");
      if (pubOf("COLD_VAULT", st.activeColdIndex) !== st.quantumColdVaultPubkey) {
        fail("quantumColdVaultPubkey");
      }
      if (
        st.quantumHashLockedPdaVault &&
        st.quantumHashLockedPdaVault !==
          deriveHashLockedQuantumPdaVault(st.xmssMasterRootHex, st.activeColdIndex).pdaAddressB58
      ) {
        fail("quantumHashLockedPdaVault");
      }
      const hotB58 = imported
        ? encodeB58(deriveEd25519PublicKeyFromSeed32(Buffer.from(imported)))
        : pubOf("QSAFE_HOT", 0);
      if (hotB58 !== st.primaryHotWalletPubkey) fail("primaryHotWalletPubkey");
      if (
        st.balanceFloorGuardAnchorPubkey &&
        pubOf("BALANCE_GUARD_ANCHOR", 0) !== st.balanceFloorGuardAnchorPubkey
      ) {
        fail("balanceFloorGuardAnchorPubkey");
      }
      if (!Array.isArray(st.ephemeralBurners) || st.ephemeralBurners.length < 1) {
        fail("ephemeralBurners");
      }
      st.ephemeralBurners.forEach((b, i) => {
        if (!b || b.index !== i || pubOf("EPHEMERAL_BURNER", i) !== b.pubkey) {
          fail(`ephemeralBurners[${i}]`);
        }
      });
      if (!isIdx(st.activeBurnerIndex) || st.activeBurnerIndex >= st.ephemeralBurners.length) {
        fail("activeBurnerIndex");
      }
      if (st.ephemeralBurners[st.activeBurnerIndex].pubkey !== st.activeBurnerPubkey) {
        fail("activeBurnerPubkey");
      }
      for (const h of st.coldRotationHistory || []) {
        if (
          !isIdx(h.retiredIndex) ||
          !isIdx(h.rotatedToIndex) ||
          pubOf("COLD_VAULT", h.retiredIndex) !== h.retiredPubkey ||
          pubOf("COLD_VAULT", h.rotatedToIndex) !== h.rotatedToPubkey
        ) {
          fail("coldRotationHistory");
        }
      }
    });
  }

  /**
   * Signs a post-quantum WOTS+/XMSS proof and durably reserves a `SIG_SEQ_RESERVE_WINDOW`
   * ahead of use so crashes or restored snapshots never reuse a one-time signature leaf.
   */
  signQuantumProof(slot, txMessageBytes) {
    const st = this.envelope.state;
    const nextSeq = this.xmssEngine.sigSeqCounter;
    if (!Number.isInteger(st.xmssSigSeqCounter) || nextSeq >= st.xmssSigSeqCounter) {
      st.xmssSigSeqCounter = nextSeq + SIG_SEQ_RESERVE_WINDOW;
      this.persistToDisk(true);
    }
    return this.xmssEngine.signTransactionQuantumProof(slot, txMessageBytes);
  }

  /**
   * Seed-holder authenticated verification: re-derives the exact XMSS subtree root and OTS
   * preimage commitment for `proof.sigSeq` from this vault's seed.
   */
  verifyOwnQuantumProof(proof, txMessageBytes) {
    if (
      !proof ||
      !Number.isInteger(proof.sigSeq) ||
      proof.sigSeq < 0 ||
      !Number.isInteger(proof.subtreeEpoch) ||
      proof.subtreeEpoch < 0
    ) {
      return {
        verified: false,
        preimageValid: false,
        wotsValid: false,
        merkleValid: false,
        reason: "NOT_ISSUED_BY_THIS_VAULT",
        authenticity: "LOCAL_VAULT_AUTHENTICATED"
      };
    }
    const epoch0RootHex = this.xmssEngine.getOrBuildXmssSubtree(0).rootHex;
    if (proof.masterRootHex !== epoch0RootHex) {
      return {
        verified: false,
        preimageValid: false,
        wotsValid: false,
        merkleValid: false,
        reason: "PINNED_MASTER_ROOT_MISMATCH",
        authenticity: "LOCAL_VAULT_AUTHENTICATED"
      };
    }
    const subtree = this.xmssEngine.getOrBuildXmssSubtree(proof.subtreeEpoch);
    const preimageBuf = this.xmssEngine.deriveLeafPreimage(proof.sigSeq);
    const expectedOtpkHex = sha256Fast(preimageBuf).toString("hex");
    zeroizeBuffer(preimageBuf);

    const out = WotsXmssEngine.verifyTransactionQuantumProof(proof, txMessageBytes, {
      expectedMasterRootHex: epoch0RootHex,
      expectedXmssRootHex: subtree.rootHex,
      expectedFinalizeOtpkHex: expectedOtpkHex
    });
    out.authenticity = "LOCAL_VAULT_AUTHENTICATED";
    return out;
  }

  async verifyPassphraseAsync(candidatePassphrase) {
    if (!candidatePassphrase || typeof candidatePassphrase !== "string") return false;
    const salt = Buffer.from(this.envelope.saltHex, "hex");
    const testKey = await pbkdf2Async(
      candidatePassphrase,
      salt,
      assertSaneKdfIterations(this.envelope),
      KDF_KEYLEN,
      KDF_DIGEST
    );
    try {
      const iv = Buffer.from(this.envelope.ivHex, "hex");
      const authTag = Buffer.from(this.envelope.authTagHex, "hex");
      const ciphertext = Buffer.from(this.envelope.ciphertextHex, "hex");
      const decipher = crypto.createDecipheriv(CIPHER_ALGO, testKey, iv);
      decipher.setAuthTag(authTag);
      const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      zeroizeBuffer(dec);
      return true;
    } catch (_) {
      return false;
    } finally {
      zeroizeBuffer(testKey);
    }
  }

  _withDecryptedSeeds(callback) {
    const aesKey = Buffer.allocUnsafe(32);
    for (let i = 0; i < 32; i++) {
      aesKey[i] = this._maskedAesKey[i] ^ this._keyMask[i];
    }
    let decrypted = null;
    let masterSeed32 = null;
    let importedHotSeed32 = null;
    try {
      const iv = Buffer.from(this.envelope.ivHex, "hex");
      const authTag = Buffer.from(this.envelope.authTagHex, "hex");
      const ciphertext = Buffer.from(this.envelope.ciphertextHex, "hex");

      const decipher = crypto.createDecipheriv(CIPHER_ALGO, aesKey, iv);
      decipher.setAuthTag(authTag);
      decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

      const hasImportedHot = decrypted[0] === 1;
      masterSeed32 = Buffer.from(decrypted.subarray(1, 33));
      if (hasImportedHot) {
        importedHotSeed32 = Buffer.from(decrypted.subarray(33, 65));
      }
      return callback(masterSeed32, importedHotSeed32);
    } catch (err) {
      if (/^(VAULT_STATE_TAMPERED|INVALID_KEY_INDEX|Unknown wallet tier)/.test(err.message)) {
        throw err;
      }
      throw new Error(`Vault authentication failed or wrong passphrase: ${err.message}`);
    } finally {
      zeroizeBuffer(aesKey);
      zeroizeBuffer(decrypted);
      zeroizeBuffer(masterSeed32);
      zeroizeBuffer(importedHotSeed32);
    }
  }

  _withTierSeed32(tier, index, callback) {
    return this._withDecryptedSeeds((masterSeed32, importedHotSeed32) => {
      let childSeed32 = null;
      if (
        index !== undefined &&
        index !== null &&
        !(Number.isInteger(index) && index >= 0 && index < 0xffffffff)
      ) {
        throw new Error(`INVALID_KEY_INDEX: index must be a non-negative integer (got ${String(index)})`);
      }
      try {
        if (tier === "COLD") {
          const idx = typeof index === "number" ? index : this.envelope.state.activeColdIndex;
          childSeed32 = deriveDomainChildSeed32(masterSeed32, "COLD_VAULT", idx);
        } else if (tier === "HOT") {
          if (importedHotSeed32) {
            childSeed32 = Buffer.from(importedHotSeed32);
          } else {
            childSeed32 = deriveDomainChildSeed32(masterSeed32, "QSAFE_HOT", 0);
          }
        } else if (tier === "BURNER") {
          const idx = typeof index === "number" ? index : this.envelope.state.activeBurnerIndex;
          childSeed32 = deriveDomainChildSeed32(masterSeed32, "EPHEMERAL_BURNER", idx);
        } else if (tier === "GUARD_ANCHOR") {
          const idx = typeof index === "number" ? index : 0;
          childSeed32 = deriveDomainChildSeed32(masterSeed32, "BALANCE_GUARD_ANCHOR", idx);
        } else {
          throw new Error(`Unknown wallet tier: ${tier}`);
        }
        const pubkey32 = deriveEd25519PublicKeyFromSeed32(childSeed32);
        return callback(childSeed32, pubkey32);
      } finally {
        zeroizeBuffer(childSeed32);
      }
    });
  }

  getPublicVaultSummary() {
    const st = this.envelope.state;
    const pdaInfo = deriveHashLockedQuantumPdaVault(st.xmssMasterRootHex, st.activeColdIndex);
    return {
      engine: this.envelope.engine,
      xmssMasterRootHex: st.xmssMasterRootHex,
      sigSeqWatermark: this.xmssEngine.sigSeqCounter,
      quantumColdVault: {
        activeIndex: st.activeColdIndex,
        pubkey: st.quantumColdVaultPubkey,
        hashLockedQuantumPdaVault: st.quantumHashLockedPdaVault || pdaInfo.pdaAddressB58,
        programId: QSAFE_PQ_VAULT_PROGRAM_ID_B58,
        keyExposedOnChain: st.coldKeyExposedOnChain,
        ed25519AccountModel: st.coldKeyExposedOnChain
          ? "ED25519_SPENT_ROTATION_NEEDED"
          : "ED25519_FRESH_OTS_COLD_ADDRESS",
        pdaVaultQuantumModel: "SHOR_IMMUNE_HASH_LOCKED_PDA_NO_ED25519_KEY",
        previousRotationsCount: st.coldRotationHistory.length
      },
      primaryHotWallet: {
        pubkey: st.primaryHotWalletPubkey,
        balanceFloorGuardAnchorPubkey:
          st.balanceFloorGuardAnchorPubkey ||
          this._withTierSeed32("GUARD_ANCHOR", 0, (_s, pub32) => encodeB58(pub32)),
        hasImportedHotKey: st.hasImportedHotKey
      },
      burnerPool: {
        activeBurnerIndex: st.activeBurnerIndex,
        activeBurnerPubkey: st.activeBurnerPubkey,
        totalBurnersDerived: st.ephemeralBurners.length,
        burners: st.ephemeralBurners
      }
    };
  }

  deriveNextBurner(label) {
    const t0 = process.hrtime.bigint();
    const nextIdx = this.envelope.state.ephemeralBurners.length;
    const pubkeyStr = this._withTierSeed32("BURNER", nextIdx, (_seed32, pub32) => encodeB58(pub32));
    const deriveUs = Number(process.hrtime.bigint() - t0) / 1e3;

    const entry = {
      index: nextIdx,
      pubkey: pubkeyStr,
      label: label || `Burner #${nextIdx}`,
      createdAt: new Date().toISOString()
    };
    this.envelope.state.ephemeralBurners.push(entry);
    this.envelope.state.activeBurnerIndex = nextIdx;
    this.envelope.state.burnerCount = this.envelope.state.ephemeralBurners.length;
    this.envelope.state.activeBurnerPubkey = pubkeyStr;
    this.persistToDisk(true);

    return {
      ...entry,
      deriveLatencyUs: Number(deriveUs.toFixed(2))
    };
  }

  dualSignTransactionBytes(txMessageBytes, opts = {}) {
    const tier = opts.tier || "HOT";
    const slot = opts.slot || 0;
    const msgBuf = Buffer.from(txMessageBytes);

    const t0 = process.hrtime.bigint();
    const { sig64, signerPubkeyB58 } = this._withTierSeed32(
      tier,
      opts.index,
      (seed32, pub32) => {
        const signature = signEd25519Seed32Native(seed32, msgBuf);
        return {
          sig64: signature,
          signerPubkeyB58: encodeB58(pub32)
        };
      }
    );
    const ed25519SignUs = Number(process.hrtime.bigint() - t0) / 1e3;

    const wireTx = Buffer.allocUnsafe(1 + 64 + msgBuf.length);
    wireTx[0] = 1;
    sig64.copy(wireTx, 1);
    msgBuf.copy(wireTx, 65);

    const quantumProof = this.signQuantumProof(slot, msgBuf);
    const totalDualSignUs = Number(process.hrtime.bigint() - t0) / 1e3;

    if (tier === "COLD") {
      this.envelope.state.coldKeyExposedOnChain = true;
    }

    return {
      tier,
      signerPubkey: signerPubkeyB58,
      signatureBase58: encodeB58(sig64),
      signatureBuffer64: sig64,
      wireTransaction: wireTx,
      wireBytes: wireTx.length,
      ed25519SignUs: Number(ed25519SignUs.toFixed(2)),
      totalDualSignUs: Number(totalDualSignUs.toFixed(2)),
      quantumProof
    };
  }

  dualSignRoundTripGuardedMessage(txMessageBytes, opts = {}) {
    const pTier = opts.primaryTier || "HOT";
    const pIdx = opts.primaryIndex ?? 0;
    const gTier = opts.guardTier || "GUARD_ANCHOR";
    const gIdx = opts.guardIndex ?? 0;
    const sSlot = opts.slot || 0;

    const msgBuf = Buffer.from(txMessageBytes);
    const { sig1, signerPubkeyB58 } = this._withTierSeed32(pTier, pIdx, (seed32, pub32) => ({
      sig1: signEd25519Seed32Native(seed32, msgBuf),
      signerPubkeyB58: encodeB58(pub32)
    }));
    const sig2 = this._withTierSeed32(gTier, gIdx, (seed32) =>
      signEd25519Seed32Native(seed32, msgBuf)
    );

    const wireTx = Buffer.allocUnsafe(1 + 128 + msgBuf.length);
    wireTx[0] = 2;
    sig1.copy(wireTx, 1);
    sig2.copy(wireTx, 65);
    msgBuf.copy(wireTx, 129);

    const quantumProof = this.signQuantumProof(sSlot, msgBuf);
    return {
      signerPubkey: signerPubkeyB58,
      signatureBase58: encodeB58(sig1),
      coSignerSignatureBase58: encodeB58(sig2),
      wireTransaction: wireTx,
      wireBytes: wireTx.length,
      quantumProof
    };
  }

  prepareColdVaultOtsSpendAndRotate(params) {
    const spendLamports = BigInt(params.spendLamports);
    const totalLamports = BigInt(params.currentColdBalanceLamports);
    const feeLamports = BigInt(params.txFeeLamports ?? 5000n);

    if (spendLamports <= 0n) {
      throw new Error("spendLamports must be > 0");
    }
    if (spendLamports + feeLamports > totalLamports) {
      throw new Error(
        `Insufficient Cold Vault balance: need ${spendLamports + feeLamports} lamports, have ${totalLamports}`
      );
    }

    const currentColdIdx = this.envelope.state.activeColdIndex;
    const nextColdIdx = currentColdIdx + 1;

    const currentColdPubB58 = this._withTierSeed32("COLD", currentColdIdx, (_s, p) => encodeB58(p));
    const nextColdPubB58 = this._withTierSeed32("COLD", nextColdIdx, (_s, p) => encodeB58(p));
    const nextHashLockedPda = deriveHashLockedQuantumPdaVault(
      this.envelope.state.xmssMasterRootHex,
      nextColdIdx
    );

    const sweepToNextColdLamports = totalLamports - spendLamports - feeLamports;

    const buildSystemTransferIx = (fromB58, toB58, lamportsBig) => {
      const data = Buffer.allocUnsafe(12);
      data.writeUInt32LE(2, 0);
      data.writeBigUInt64LE(BigInt(lamportsBig), 4);
      return {
        programId: SYSTEM_PROGRAM_ID_B58,
        keys: [
          { pubkey: fromB58, isSigner: true, isWritable: true },
          { pubkey: toB58, isSigner: false, isWritable: true }
        ],
        data
      };
    };

    const instructions = [
      buildSystemTransferIx(currentColdPubB58, params.destinationPubkey, spendLamports)
    ];

    if (sweepToNextColdLamports > 0n) {
      instructions.push(
        buildSystemTransferIx(currentColdPubB58, nextColdPubB58, sweepToNextColdLamports)
      );
    }

    this.envelope.state.coldRotationHistory.push({
      retiredIndex: currentColdIdx,
      retiredPubkey: currentColdPubB58,
      rotatedToIndex: nextColdIdx,
      rotatedToPubkey: nextColdPubB58,
      rotatedToQuantumPdaVault: nextHashLockedPda.pdaAddressB58,
      spendLamports: spendLamports.toString(),
      sweptLamports: sweepToNextColdLamports.toString(),
      rotatedAt: new Date().toISOString()
    });
    this.envelope.state.activeColdIndex = nextColdIdx;
    this.envelope.state.quantumColdVaultPubkey = nextColdPubB58;
    this.envelope.state.quantumHashLockedPdaVault = nextHashLockedPda.pdaAddressB58;
    this.envelope.state.coldKeyExposedOnChain = false;
    this.persistToDisk(true);

    return {
      signingColdIndex: currentColdIdx,
      retiredColdVaultPubkey: currentColdPubB58,
      newQuantumColdVaultIndex: nextColdIdx,
      newQuantumColdVaultPubkey: nextColdPubB58,
      newHashLockedQuantumPdaVault: nextHashLockedPda.pdaAddressB58,
      spendLamports,
      sweepToNextColdLamports,
      remainingOnExposedVaultLamports: 0n,
      instructions
    };
  }

  buildQuantumMemoIx(slot, sigSeqHint = 0) {
    const preimage = this.xmssEngine.deriveLeafPreimage(sigSeqHint);
    const otpkHex = sha256Fast(preimage).toString("hex");
    zeroizeBuffer(preimage);
    const memoStr = `QSAFE:WOTS-XMSS:S=${slot}:Y=${otpkHex.slice(0, 24)}`;
    return {
      programId: MEMO_PROGRAM_ID_B58,
      keys: [],
      data: Buffer.from(memoStr, "utf8")
    };
  }

  exportHotWalletBase58() {
    return this._withTierSeed32("HOT", 0, (seed32, pub32) => {
      const full64 = Buffer.concat([seed32, pub32]);
      try {
        return encodeB58(full64);
      } finally {
        zeroizeBuffer(full64);
      }
    });
  }

  persistToDisk(allowOverwrite = true) {
    if (!this.vaultFilePath) return;
    const safePath = validateSafeVaultFilePath(this.vaultFilePath, allowOverwrite);
    const dir = path.dirname(safePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmpFile = `${safePath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(this.envelope, null, 2), { mode: 0o600 });
    fs.renameSync(tmpFile, safePath);
  }

  lockAndDestroy() {
    zeroizeBuffer(this._maskedAesKey);
    zeroizeBuffer(this._keyMask);
    if (this.xmssEngine) {
      this.xmssEngine.destroy();
    }
  }
}

module.exports = {
  VaultCryptoEngine,
  WotsXmssEngine,
  QSAFE_PQ_VAULT_PROGRAM_ID_B58,
  DEFAULT_VAULT_DIR,
  deriveHashLockedQuantumPdaVault,
  validateSafeVaultFilePath,
  zeroizeBuffer,
  encodeB58,
  decodeB58,
  deriveEd25519PublicKeyFromSeed32,
  signEd25519Seed32Native,
  verifyEd25519Native,
  WOTS_MSG_CHAINS,
  WOTS_CSUM_CHAINS,
  WOTS_TOTAL_CHAINS,
  MIN_PASSPHRASE_LENGTH,
  KDF_MIN_ITERATIONS,
  KDF_MAX_ITERATIONS
};
