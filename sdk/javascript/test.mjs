import assert from 'node:assert/strict';
import { OpenProofIdentity } from './openproof.js';

const storage = new Map();
globalThis.sessionStorage = {
  setItem: (key, value) => storage.set(key, value),
  getItem: key => storage.get(key) ?? null,
  removeItem: key => storage.delete(key),
};

const client = new OpenProofIdentity({
  issuer: 'https://identity.example', clientId: 'tegra-web',
  redirectUri: 'https://tegra.example/auth/callback', scopes: ['openid', 'profile'],
});
const url = await client.beginLogin();
assert.equal(url.searchParams.get('response_type'), 'code');
assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
assert.equal(url.searchParams.get('code_challenge').length, 43);
assert.ok(storage.has(`openproof:${url.searchParams.get('state')}`));
const callbackState = url.searchParams.get('state');
globalThis.fetch = async () => ({ ok: true, json: async () => ({ access_token: 'test' }) });
await client.handleCallback(
  `https://tegra.example/auth/callback?code=code&state=${callbackState}&iss=${encodeURIComponent('https://identity.example')}`,
);
const second = await client.beginLogin();
const secondState = second.searchParams.get('state');
await assert.rejects(
  client.handleCallback(
    `https://tegra.example/auth/callback?code=code&state=${secondState}&iss=${encodeURIComponent('https://evil.example')}`,
  ),
  /Invalid OpenProof callback/,
);
console.log('OpenProof JavaScript SDK tests passed');
