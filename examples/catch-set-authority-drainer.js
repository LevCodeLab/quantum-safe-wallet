"use strict";

/**
 * Runnable Example 2: Catching Hidden SPL-Token::SetAuthority & signMessage Phishing
 * Run: node examples/catch-set-authority-drainer.js
 */

const crypto = require("crypto");
const {
  BytecodeDrainerFirewall,
  compileV0MessageFast,
  buildSetComputeUnitLimitIx,
  buildSolTransferIx,
  encodeB58,
  decodeB58,
  deriveEd25519PublicKeyFromSeed32,
  SPL_TOKEN_PROGRAM_ID
} = require("../src");

function randomPubkey() {
  return encodeB58(deriveEd25519PublicKeyFromSeed32(crypto.randomBytes(32)));
}

const userWallet = randomPubkey();
const userUsdcAta = randomPubkey();
const merchantTipDest = randomPubkey();
const drainerPubkey = randomPubkey();
const recentBlockhash = randomPubkey();

// Build a sneaky 3-instruction V0 transaction where ix #2 silently steals ATA ownership
const setAuthorityData = Buffer.allocUnsafe(35);
setAuthorityData[0] = 6; // SPL-Token::SetAuthority
setAuthorityData[1] = 2; // AuthorityType::AccountOwner
setAuthorityData[2] = 1; // COption::Some
decodeB58(drainerPubkey).copy(setAuthorityData, 3);

const sneakyDappTx = compileV0MessageFast(userWallet, recentBlockhash, [
  buildSetComputeUnitLimitIx(80_000),
  buildSolTransferIx(userWallet, merchantTipDest, 5_000_000n),
  {
    programId: SPL_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: userUsdcAta, isSigner: false, isWritable: true },
      { pubkey: userWallet, isSigner: true, isWritable: false }
    ],
    data: setAuthorityData
  }
]);

const txAudit = BytecodeDrainerFirewall.inspectTransactionBytes(sneakyDappTx, {
  userPubkeyB58: userWallet,
  userTokenAtas: [userUsdcAta]
});

console.log("=== Static Solana Firewall Example ===");
console.log("Tx Safe?         :", txAudit.safe);
console.log("Rule Triggered   :", txAudit.ruleTriggered);
console.log("Blocked Reason   :", txAudit.reason);
console.log("Inspect Latency  :", `${txAudit.inspectLatencyUs} us`);

// Also test signMessage() phishing where raw V0 transaction bytes are passed as a login message
const msgPhishAudit = BytecodeDrainerFirewall.inspectSignMessagePayload(sneakyDappTx, userWallet);
console.log("\n=== signMessage() Phishing Check ===");
console.log("Message Safe?    :", msgPhishAudit.safe);
console.log("Rule Triggered   :", msgPhishAudit.ruleTriggered);
