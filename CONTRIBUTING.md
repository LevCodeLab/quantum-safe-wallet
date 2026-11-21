# contributing to quantum-safe-wallet

Thanks for poking around the repo, bhai.

Keeping crypto and wallet code tiny and readable is half the battle, so here are the ground rules.

## setup

* Install Node.js 20 or newer.
* Do not add any npm dependencies (`package.json` stays zero-dep on purpose).
* Run `npm test` before and after your edit.
* Run `npm run demo` to make sure the terminal walkthrough stays green.
* Run `npm run lint:brand` to keep formatting and naming clean.

## adding a new firewall rule

* Add the binary byte check inside `src/drainer_firewall.js`.
* Fail closed if an instruction buffer is truncated or weird.
* Return a clear `RULE_XX` code so callers know why the tx got blocked.
* Add both a bad payload test and a clean payload test inside `test/vault-and-firewall.test.js`.

## touching vault crypto

* Never log or cache raw decrypted seeds or AES keys.
* Always zero out temporary key buffers in a `finally` block (`zeroizeBuffer`).
* Keep `sigSeq` strictly moving forward so a one-time WOTS+ key is never used twice.
* Keep `COLD` keys blocked on dApp signing routes inside `src/wallet_server.js`.

## pull requests

* Keep commits small and focused on one thing at a time.
* Make sure `node examples/wots-sign-verify.js` and `node examples/catch-set-authority-drainer.js` run with exit code 0.
