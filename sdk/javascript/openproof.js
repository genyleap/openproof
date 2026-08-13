const base64Url = bytes => btoa(String.fromCharCode(...bytes))
  .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const random = size => base64Url(crypto.getRandomValues(new Uint8Array(size)));
const challenge = async verifier => base64Url(new Uint8Array(
  await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
const decodeBase64Url = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid OpenProof ID token');
  }
  const padded = value.replaceAll('-', '+').replaceAll('_', '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
};
const decodeJsonPart = value => {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    return parsed;
  } catch {
    throw new Error('Invalid OpenProof ID token');
  }
};
const audienceMatches = (claims, clientId) => {
  if (typeof claims.aud === 'string') return claims.aud === clientId;
  if (!Array.isArray(claims.aud) || !claims.aud.every(value => typeof value === 'string')
      || !claims.aud.includes(clientId)) return false;
  return claims.aud.length === 1 || claims.azp === clientId;
};
const accessTokenHash = async value => {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(value)));
  return base64Url(digest.slice(0, digest.length / 2));
};

const assertConfig = ({ issuer, clientId, redirectUri, scopes }) => {
  if (!clientId || !redirectUri || !Array.isArray(scopes) || scopes.length === 0) {
    throw new TypeError('Invalid OpenProof client configuration');
  }
  let parsedIssuer;
  let parsedRedirect;
  try {
    parsedIssuer = new URL(issuer);
    parsedRedirect = new URL(redirectUri);
  } catch {
    throw new TypeError('Invalid OpenProof client configuration');
  }
  const loopbackHttp = parsedIssuer.protocol === 'http:'
    && ['127.0.0.1', '[::1]', 'localhost'].includes(parsedIssuer.hostname);
  if ((parsedIssuer.protocol !== 'https:' && !loopbackHttp)
      || parsedIssuer.username || parsedIssuer.password
      || parsedIssuer.search || parsedIssuer.hash || parsedRedirect.username
      || parsedRedirect.password) {
    throw new TypeError('Invalid OpenProof client configuration');
  }
};

export class OpenProofIdentity {
  constructor({ issuer, clientId, redirectUri, scopes = ['openid', 'profile'] }) {
    const config = { issuer, clientId, redirectUri, scopes };
    assertConfig(config);
    this.issuer = issuer.replace(/\/$/, '');
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.scopes = [...new Set(scopes)].sort();
  }

  async beginLogin() {
    const verifier = random(32);
    const state = random(32);
    const nonce = random(24);
    sessionStorage.setItem(`openproof:${state}`, JSON.stringify({ verifier, nonce }));
    const url = new URL(`${this.issuer}/oauth/authorize`);
    url.search = new URLSearchParams({
      response_type: 'code', client_id: this.clientId,
      redirect_uri: this.redirectUri, scope: this.scopes.join(' '),
      code_challenge: await challenge(verifier), code_challenge_method: 'S256',
      state, nonce,
    });
    return url;
  }

  async login() {
    location.assign(await this.beginLogin());
  }

  async handleCallback(currentUrl = location.href) {
    const url = new URL(currentUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const returnedIssuer = url.searchParams.get('iss');
    if (!code || !state || returnedIssuer !== this.issuer) {
      throw new Error('Invalid OpenProof callback');
    }
    const key = `openproof:${state}`;
    const transaction = JSON.parse(sessionStorage.getItem(key) ?? 'null');
    sessionStorage.removeItem(key);
    if (!transaction?.verifier || !transaction?.nonce) {
      throw new Error('Unknown OpenProof transaction');
    }
    const tokens = await this.exchangeCode(code, transaction.verifier);
    if (!this.scopes.includes('openid')) return tokens;
    if (typeof tokens.id_token !== 'string' || typeof tokens.access_token !== 'string') {
      throw new Error('Invalid OpenProof token response');
    }
    const claims = await this.#verifyIdToken(
      tokens.id_token, transaction.nonce, tokens.access_token);
    return { ...tokens, id_token_claims: claims };
  }

  async exchangeCode(code, verifier) {
    const body = new URLSearchParams({
      grant_type: 'authorization_code', client_id: this.clientId,
      code, redirect_uri: this.redirectUri, code_verifier: verifier,
    });
    return this.#tokenRequest(body);
  }

  async refresh(refreshToken) {
    if (!refreshToken) throw new TypeError('Refresh token is required');
    return this.#tokenRequest(new URLSearchParams({
      grant_type: 'refresh_token', client_id: this.clientId,
      refresh_token: refreshToken,
    }));
  }

  async userInfo(accessToken) {
    if (!accessToken) throw new TypeError('Access token is required');
    const response = await fetch(`${this.issuer}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${accessToken}` }, credentials: 'omit',
    });
    if (!response.ok) throw new Error('OpenProof UserInfo request failed');
    return response.json();
  }

  async #verifyIdToken(token, expectedNonce, accessToken) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid OpenProof ID token');
    const header = decodeJsonPart(parts[0]);
    const claims = decodeJsonPart(parts[1]);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid
        || claims.iss !== this.issuer || !audienceMatches(claims, this.clientId)
        || claims.nonce !== expectedNonce || typeof claims.sub !== 'string' || !claims.sub
        || typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)
        || typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) {
      throw new Error('Invalid OpenProof ID token');
    }
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp <= now - 60 || claims.iat > now + 60
        || (claims.nbf !== undefined
          && (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf)
            || claims.nbf > now + 60))) {
      throw new Error('Invalid OpenProof ID token');
    }
    if (claims.at_hash !== undefined
        && (typeof claims.at_hash !== 'string'
          || claims.at_hash !== await accessTokenHash(accessToken))) {
      throw new Error('Invalid OpenProof ID token');
    }

    const response = await fetch(`${this.issuer}/.well-known/jwks.json`, {
      credentials: 'omit',
    });
    if (!response.ok) throw new Error('OpenProof JWKS request failed');
    const document = await response.json();
    const candidates = Array.isArray(document?.keys)
      ? document.keys.filter(key => key?.kid === header.kid && key.kty === 'RSA'
        && (!key.alg || key.alg === 'RS256') && (!key.use || key.use === 'sig')
        && (!Array.isArray(key.key_ops) || key.key_ops.includes('verify')))
      : [];
    if (candidates.length !== 1) throw new Error('Invalid OpenProof ID token');
    try {
      const key = await crypto.subtle.importKey(
        'jwk', candidates[0],
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
      const verified = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5', key, decodeBase64Url(parts[2]),
        new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
      if (!verified) throw new Error();
    } catch {
      throw new Error('Invalid OpenProof ID token');
    }
    return claims;
  }

  async #tokenRequest(body) {
    const response = await fetch(`${this.issuer}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body, credentials: 'omit',
    });
    if (!response.ok) throw new Error('OpenProof token exchange failed');
    return response.json();
  }
}
