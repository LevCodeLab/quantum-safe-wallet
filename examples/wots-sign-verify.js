"use strict";

/**
 * Runnable Example 1: Stateful WOTS+ (67-Chain) + XMSS Merkle Sign & Verify
 * Run: node examples/wots-sign-verify.js
 */

const crypto = require("crypto");
const { WotsXmssEngine } = require("../src");

const masterSeed32 = crypto.randomBytes(32);
const pqSigner = new WotsXmssEngine(masterSeed32, 0, { subtreeHeight: 4 });

console.log("=== WOTS+ (w=16, 67 chains) + XMSS Subtree Demo ===");
console.log("Pinned XMSS Root :", pqSigner.masterRootHex);

const message1 = Buffer.from("Send 1.25 SOL to cold savings");
const message2 = Buffer.from("Send 0.10 SOL to devnet faucet");

const proof1 = pqSigner.signTransactionQuantumProof(320_500_001, message1);
const proof2 = pqSigner.signTransactionQuantumProof(320_500_002, message2);

console.log(`Leaf #0 sigSeq   : ${proof1.sigSeq} | WOTS bytes: ${proof1.wotsWireBytes} | Merkle path: ${proof1.merklePathBytes}B`);
console.log(`Leaf #1 sigSeq   : ${proof2.sigSeq} | WOTS bytes: ${proof2.wotsWireBytes} | Merkle path: ${proof2.merklePathBytes}B`);

// Third-party verifier only needs the single 32-byte XMSS Merkle root
const ok1 = WotsXmssEngine.verifyTransactionQuantumProof(proof1, message1, {
  expectedMasterRootHex: pqSigner.masterRootHex
});
console.log("Verify #1        :", ok1.verified, "| authenticity:", ok1.authenticity);

// Attempt to verify proof1 against altered message2
const forged = WotsXmssEngine.verifyTransactionQuantumProof(proof1, message2, {
  expectedMasterRootHex: pqSigner.masterRootHex
});
console.log("Tampered check   :", forged.verified, "| reason:", forged.reason);

// Reject OTS replay when verifier watermark has already advanced past sigSeq 0
const replay = WotsXmssEngine.verifyTransactionQuantumProof(proof1, message1, {
  expectedMasterRootHex: pqSigner.masterRootHex,
  minAcceptedSigSeq: 1
});
console.log("Replay check     :", replay.verified, "| reason:", replay.reason);

pqSigner.destroy();
