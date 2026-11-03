---
status: accepted
date: 2026-11-03
---

# Base Sepolia reads use ordered RPC failover

Public RPC rate limits and differing finalized heights were refusing Mac
registrations even when one provider was healthy.

Use one healthy Base Sepolia provider, with ordered failover and per-provider
exponential backoff for HTTP 429 and JSON-RPC quota errors. Honor `Retry-After`.
Keep chain ID, finalized height/freshness, deployed code hash and EIP-1898
canonical block pins. A replacement snapshot provider must match its block
number and hash. Receipt confirmation still checks the transaction block hash.
Contract reverts propagate immediately. Exhausted providers remain an error.

Helios has a [Base Sepolia configuration](https://github.com/a16z/helios/blob/master/opstack/src/config.rs),
but its [OP consensus client](https://github.com/a16z/helios/blob/master/opstack/src/consensus.rs)
authenticates unsafe sequencer gossip and never sends a finalized block.
It cannot supply the finalized snapshots used to authorize deposit credit.
Use the failover reader until a light client supplies authenticated finalized
Base Sepolia headers. The fallback trusts the selected public RPC for state;
block pinning prevents mixing snapshots, and code pins retain contract identity.
Before this change one lying public provider was outvoted. Now a single provider
answers the broker's trust reads: deposits and exit requests that become credit
(`payments.mjs` `syncBalance`), node class measurements and broker signer
(`register`), and the App Attest enrollment key, CDRegistry rpIdHash, category
and canary reads used for guest admission. By default the list is the configured
`rpc` followed by the public providers. A lying provider could mint credit or
admit a guest that is not attested. This is accepted for the testnet only.

The page retains its existing reader.
