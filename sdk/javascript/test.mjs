import assert from 'node:assert/strict';
import { OpenProofIdentity } from './openproof.js';

const storage = new Map();
globalThis.sessionStorage = {
  setItem: (key, value) => storage.set(key, value),
  getItem: key => storage.get(key) ?? null,
  removeItem: key => storage.delete(key),
};

const encode = bytes => Buffer.from(bytes).toString('base64url');
const jsonPart = value => encode(new TextEncoder().encode(JSON.stringify(value)));
const keyPair = await crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true, ['sign', 'verify']);
const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
Object.assign(publicJwk, { kid: 'sdk-test-key', alg: 'RS256', use: 'sig' });

const signIdToken = async claims => {
  const header = jsonPart({ alg: 'RS256', typ: 'JWT', kid: publicJwk.kid });
  const payload = jsonPart(claims);
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', keyPair.privateKey,
    new TextEncoder().encode(signingInput));
  return `${signingInput}.${encode(signature)}`;
};

const issuer = 'https://identity.example';
const clientId = 'example-web';
const redirectUri = 'https://app.example.com/auth/callback';
const client = new OpenProofIdentity({
  issuer, clientId, redirectUri, scopes: ['openid', 'profile'],
});
for (const invalidIssuer of [
  'http://localhost.evil.example',
  'http://127.0.0.1.evil.example',
  'https://user:password@identity.example',
  'https://identity.example?issuer=other',
]) {
  assert.throws(() => new OpenProofIdentity({
    issuer: invalidIssuer, clientId, redirectUri, scopes: ['openid'],
  }), /Invalid OpenProof client configuration/);
}
let tokenResponse;
let jwks = [publicJwk];
globalThis.fetch = async url => {
  if (String(url) === `${issuer}/oauth/token`) {
    return { ok: true, json: async () => tokenResponse };
  }
  if (String(url) === `${issuer}/.well-known/jwks.json`) {
    return { ok: true, json: async () => ({ keys: jwks }) };
  }
  throw new Error(`Unexpected test URL: ${url}`);
};

const begin = async () => {
  const url = await client.beginLogin();
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('code_challenge').length, 43);
  const state = url.searchParams.get('state');
  const transaction = JSON.parse(storage.get(`openproof:${state}`));
  assert.ok(transaction.verifier);
  assert.ok(transaction.nonce);
  return { state, nonce: transaction.nonce };
};
const callback = state => `${redirectUri}?code=code&state=${state}&iss=${encodeURIComponent(issuer)}`;
const claims = (nonce, overrides = {}) => ({
  iss: issuer,
  aud: clientId,
  sub: 'identity-42',
  nonce,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 300,
  ...overrides,
});

const valid = await begin();
tokenResponse = {
  access_token: 'access-token',
  token_type: 'Bearer',
  expires_in: 300,
  id_token: await signIdToken(claims(valid.nonce)),
};
const accepted = await client.handleCallback(callback(valid.state));
assert.equal(accepted.id_token_claims.sub, 'identity-42');
assert.equal(storage.has(`openproof:${valid.state}`), false);

const issuerMismatch = await begin();
await assert.rejects(
  client.handleCallback(
    `${redirectUri}?code=code&state=${issuerMismatch.state}&iss=${encodeURIComponent('https://evil.example')}`,
  ),
  /Invalid OpenProof callback/,
);

const nonceMismatch = await begin();
tokenResponse = {
  access_token: 'access-token',
  id_token: await signIdToken(claims('attacker-nonce')),
};
await assert.rejects(
  client.handleCallback(callback(nonceMismatch.state)),
  /Invalid OpenProof ID token/,
);

const expired = await begin();
tokenResponse = {
  access_token: 'access-token',
  id_token: await signIdToken(claims(expired.nonce, { exp: 1 })),
};
await assert.rejects(
  client.handleCallback(callback(expired.state)),
  /Invalid OpenProof ID token/,
);

for (const override of [
  { iss: 'https://evil.example' },
  { aud: 'other-client' },
  { aud: [clientId, 'other-client'] },
  { iat: Math.floor(Date.now() / 1000) + 600 },
  { at_hash: 'invalid-access-token-hash' },
]) {
  const boundary = await begin();
  tokenResponse = {
    access_token: 'access-token',
    id_token: await signIdToken(claims(boundary.nonce, override)),
  };
  await assert.rejects(
    client.handleCallback(callback(boundary.state)),
    /Invalid OpenProof ID token/,
  );
}

const ambiguousKey = await begin();
jwks = [publicJwk, { ...publicJwk }];
tokenResponse = {
  access_token: 'access-token',
  id_token: await signIdToken(claims(ambiguousKey.nonce)),
};
await assert.rejects(
  client.handleCallback(callback(ambiguousKey.state)),
  /Invalid OpenProof ID token/,
);
jwks = [publicJwk];

const badSignature = await begin();
const signed = await signIdToken(claims(badSignature.nonce));
const parts = signed.split('.');
const signature = Buffer.from(parts[2], 'base64url');
signature[0] ^= 0xff;
tokenResponse = {
  access_token: 'access-token',
  id_token: `${parts[0]}.${parts[1]}.${signature.toString('base64url')}`,
};
await assert.rejects(
  client.handleCallback(callback(badSignature.state)),
  /Invalid OpenProof ID token/,
);

console.log('OpenProof JavaScript SDK tests passed');
