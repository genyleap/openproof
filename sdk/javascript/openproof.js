const base64Url = bytes => btoa(String.fromCharCode(...bytes))
  .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const random = size => base64Url(crypto.getRandomValues(new Uint8Array(size)));
const challenge = async verifier => base64Url(new Uint8Array(
  await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));

const assertConfig = ({ issuer, clientId, redirectUri, scopes }) => {
  if (!issuer?.startsWith('https://') && !issuer?.startsWith('http://127.0.0.1')
      && !issuer?.startsWith('http://localhost')) throw new TypeError('Invalid OpenProof issuer');
  if (!clientId || !redirectUri || !Array.isArray(scopes) || scopes.length === 0) {
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
    if (!transaction?.verifier) throw new Error('Unknown OpenProof transaction');
    return this.exchangeCode(code, transaction.verifier);
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
