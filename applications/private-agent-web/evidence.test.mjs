import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Wallet } from 'ethers';
import { report, model, nonce, policy, recording, responseFor } from './test-fixtures/near.mjs';
const envelope = { provider: 'near', model, mode: 'broker-e2ee', report };
const key = report.model_attestations[0].signing_public_key;
test('authenticates recorded NEAR CPU, gateway SPKI, compose manager, model key and NVIDIA evidence without broker verdict', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: recording.now });
  const originalFetch = globalThis.fetch, originalNow = Date.now;
  globalThis.fetch = async url => { const r = responseFor(String(url)); assert(r, 'recorded network response'); return new Response(Buffer.from(r.body,'base64'), {status:r.status,headers:r.headers}); };
  Date.now = () => recording.now;
  try {
    const { checkEvidence } = await import('./evidence.mjs');
    await assert.rejects(checkEvidence({ ...envelope, verification: 'verified', report: undefined }, model, recording.now, nonce, key, policy), /TLS key binding/);
    await assert.rejects(checkEvidence(envelope, model, recording.now, '12'.repeat(32), key, policy), /nonce/);
    await assert.rejects(checkEvidence(envelope, model, recording.now, nonce, key, { ...policy, gatewayComposeHashes: [] }), /provenance/);
    await assert.rejects(checkEvidence(envelope, model, recording.now, nonce, Wallet.createRandom().signingKey.publicKey, policy), /differs from the attested/);
    const unboundGateway = { ...report, gateway_attestation: { ...report.gateway_attestation, tls_cert_fingerprint: '00'.repeat(32) } };
    await assert.rejects(checkEvidence({ ...envelope, report: unboundGateway }, model, recording.now, nonce, key, policy), /signerTlsBinding/);
    const checked = await checkEvidence({ ...envelope, verification: 'untrusted' }, model, recording.now, nonce, key, policy);
    assert.equal(checked.browser.fullQuoteVerifiedBy, 'browser');
    assert.equal(checked.models[0].gpuEvidence, 'verified');
    assert.equal(checked.tls.livePeerSpki, 'not-observable-in-browser');

  } finally { globalThis.fetch=originalFetch; Date.now=originalNow; }
});
