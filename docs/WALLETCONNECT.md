# WalletConnect and EVM wallet integration

OpenProof owns the authentication ceremony. WalletConnect is an optional client-side
transport for reaching an EVM wallet; it does not replace OpenProof SIWE verification,
session issuance, account linking, nonce handling, domain binding or chain binding.

The recommended browser strategy is hybrid:

1. use an injected EIP-1193 provider discovered through EIP-6963 when one exists;
2. use WalletConnect v2 for mobile wallets, QR pairing and wallets on another device;
3. keep OpenProof's native mobile handoff only as an optional compatibility fallback.

This ordering gives installed browser wallets the shortest path while avoiding the
poor UX of opening the relying application inside a wallet's embedded dapp browser.

## Server-side OpenProof configuration

Enable the wallet provider and bind SIWE to the exact relying-party origin:

```bash
OPENPROOF_ETHEREUM_WALLET_ENABLED=true
OPENPROOF_WEB3_DOMAIN=identity.example.com
OPENPROOF_WEB3_URI=https://identity.example.com/account
```

EOA authentication does not require an RPC endpoint. OpenProof recovers the signer
locally. Configure chain-specific RPC endpoints only when smart-account verification
is required:

```bash
OPENPROOF_ETHEREUM_RPC_ENDPOINTS='1=https://...;8453=https://...;42161=https://...'
```

OpenProof verifies deployed ERC-1271 wallets and ERC-6492 counterfactual signatures
through the configured chain-specific RPC mapping. The wallet's active positive EVM
chain ID is supplied per ceremony; OpenProof does not force a network switch.

## Configure WalletConnect / Reown in the relying application

WalletConnect configuration belongs to the browser or mobile application integrating
OpenProof, not to the OpenProof protocol core.

Create a project in the Reown / WalletConnect dashboard and allowlist the HTTPS origin
that serves the wallet UI, for example:

```text
https://app.example.com
```

Store the project ID in application configuration rather than committing a deployment-
specific value to source control. A typical deployment uses:

```bash
REOWN_PROJECT_ID=<32-character-project-id>
```

The project ID is a client identifier, not a private signing secret. Domain allowlisting
should still be enabled so the project is not freely reusable from unrelated origins.

## Client dependencies

One lightweight integration is `@walletconnect/ethereum-provider`:

```bash
npm install @walletconnect/ethereum-provider
```

Load the WalletConnect bundle lazily. Users with an injected wallet should not download
the remote-wallet transport just to authenticate with a local extension.

## Recommended provider selection

Use EIP-6963 to enumerate injected wallets. Do not assume that `window.ethereum`
identifies the user's intended wallet when multiple providers are installed.

Conceptually:

```javascript
const injected = discoverEip6963Providers();

if (injected.length === 1) {
  await authenticateWithOpenProof(injected[0].provider);
} else if (injected.length > 1) {
  showWalletPicker(injected);
} else if (reownProjectId) {
  const provider = await connectWithWalletConnect(reownProjectId);
  await authenticateWithOpenProof(provider);
} else {
  showCompatibilityFallback();
}
```

The local-wallet path and the WalletConnect path should both expose the same small
EIP-1193 surface to the OpenProof authentication code: `eth_requestAccounts`,
`eth_chainId` and `personal_sign`.

## WalletConnect provider example

```javascript
import { EthereumProvider } from "@walletconnect/ethereum-provider";

export async function connectWithWalletConnect(projectId) {
  const provider = await EthereumProvider.init({
    projectId,
    optionalChains: [1, 10, 137, 8453, 42161, 43114],
    optionalMethods: ["personal_sign"],
    optionalEvents: ["accountsChanged", "chainChanged", "disconnect"],
    showQrModal: true,
    metadata: {
      name: "Example App",
      description: "Sign in with OpenProof",
      url: "https://app.example.com",
      icons: ["https://app.example.com/icon.svg"],
      redirect: { universal: "https://app.example.com/account" }
    }
  });

  await provider.connect();
  return provider;
}
```

Choose optional chains that the relying application actually supports. OpenProof itself
does not impose a fixed wallet chain for EOA authentication.

## Complete the OpenProof SIWE ceremony

After obtaining an EIP-1193 provider, use the wallet's current address and chain:

```javascript
async function authenticateWithOpenProof(wallet) {
  const [address] = await wallet.request({ method: "eth_requestAccounts" });
  const chainHex = await wallet.request({ method: "eth_chainId" });
  const chainId = BigInt(chainHex).toString(10);

  const start = await fetch("/auth/web3/start", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "ethereum-wallet", address, chain_id: chainId })
  }).then(async response => {
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  });

  if (start.address.toLowerCase() !== address.toLowerCase()) {
    throw new Error("OpenProof returned a different wallet address");
  }
  if (String(start.chain_id) !== chainId) {
    throw new Error("OpenProof returned a different wallet chain");
  }

  const messageHex = "0x" + Array.from(
    new TextEncoder().encode(start.message),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");

  const signature = await wallet.request({
    method: "personal_sign",
    params: [messageHex, address]
  });

  const complete = await fetch("/auth/web3/complete", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: start.message, signature })
  });

  if (!complete.ok) throw new Error(await complete.text());
}
```

Sign the exact message returned by OpenProof. Do not rebuild the SIWE message in the
client and do not allow the wallet transport to substitute the nonce, domain, URI,
address or chain.

## Linking a wallet to an existing identity

For an authenticated account-management UI, use the same transport and signature flow
against:

```text
POST /account/connections/web3/start
POST /account/connections/web3/complete
```

The current OpenProof session identifies the canonical account being modified. A
successful connection completion attaches the wallet as a sign-in method; it does not
mint a second identity.

## Compatibility handoff

OpenProof also exposes its native cross-browser mobile handoff:

```text
POST /auth/web3/handoff
POST /auth/web3/handoff/redeem
```

and the authenticated account-linking equivalent. This flow is useful when an
application cannot use WalletConnect. The originating browser keeps the redeem ticket;
only the publisher ticket is sent to the wallet browser.

For a modern public web application, prefer WalletConnect for remote wallets and keep
the native handoff as a fallback rather than the primary mobile experience.

## Security checklist

- keep SIWE verification and session issuance in OpenProof;
- never send a seed phrase or private key to OpenProof, WalletConnect or application code;
- preserve the exact OpenProof challenge message through signing and completion;
- validate the returned wallet address and chain against the OpenProof start response;
- use HTTPS and configure the exact `OPENPROOF_WEB3_DOMAIN` / `OPENPROOF_WEB3_URI`;
- allowlist the relying application's origin in the Reown / WalletConnect project;
- request only the wallet methods and chains the application needs;
- discover injected providers with EIP-6963 instead of silently choosing one;
- keep WalletConnect lazy-loaded when it is only a remote-wallet fallback;
- configure RPC endpoints only for smart-account chains that must be verified;
- retain OpenProof's last-sign-in-method protections when disconnecting wallets.

## UX checklist

A good wallet picker separates providers that are already available in the browser
from remote wallets. Suggested presentation:

```text
In this browser
  MetaMask
  Rabby

Mobile or another device
  WalletConnect
```

Do not show a generic Ethereum logo for every detected wallet when EIP-6963 supplies
the wallet's name and icon. Avoid forcing users into an embedded wallet dapp browser
when WalletConnect can open the wallet app or present a desktop QR code.

The application may persist a WalletConnect pairing/session for convenience, but each
OpenProof authentication or account-linking operation still starts a fresh server-bound
SIWE challenge.
