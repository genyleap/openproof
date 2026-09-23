import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const HOST = process.env.OPENPROOF_DOCS_MCP_HOST ?? '127.0.0.1';
const PORT = Number.parseInt(process.env.OPENPROOF_DOCS_MCP_PORT ?? '8792', 10);
const VERSION = '1.0.0';
const HANDBOOK = process.env.OPENPROOF_DOCS_MCP_HANDBOOK
  ?? path.join(ROOT, 'docs', 'HANDBOOK.md');
const OPENAPI = process.env.OPENPROOF_DOCS_MCP_OPENAPI
  ?? path.join(ROOT, 'docs', 'openapi.yaml');

const URLS = {
  handbook: 'https://docs.genyleap.com/openproof/handbook',
  develop: 'https://docs.genyleap.com/openproof/develop',
  install: 'https://docs.genyleap.com/openproof/install',
  providers: 'https://docs.genyleap.com/openproof/providers',
  api: 'https://docs.genyleap.com/openproof/api/',
  openapi: 'https://docs.genyleap.com/openproof/api/openapi.yaml',
  ai: 'https://docs.genyleap.com/openproof/ai',
  llms: 'https://docs.genyleap.com/openproof/llms.txt',
  llmsFull: 'https://docs.genyleap.com/openproof/llms-full.txt',
  mcp: 'https://docs.genyleap.com/openproof/mcp',
};

const result = (text, extra = {}) => ({
  content: [{ type: 'text', text }],
  ...extra,
});

const normalize = value => String(value ?? '').trim().toLowerCase();

async function handbookText() {
  return readFile(HANDBOOK, 'utf8');
}

async function openapiText() {
  return readFile(OPENAPI, 'utf8');
}

async function currentOpenProofVersion() {
  const yaml = await openapiText();
  const match = /^  version:\s*([^\s#]+)\s*$/m.exec(yaml);
  return match?.[1] ?? 'unknown';
}

function sectionFromMarkdown(markdown, title) {
  const lines = markdown.split(/\r?\n/);
  const wanted = normalize(title);
  let start = -1;
  let level = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^(#{1,6})\s+(.+?)\s*$/.exec(lines[i]);
    if (!match) continue;
    if (normalize(match[2]).includes(wanted)) {
      start = i;
      level = match[1].length;
      break;
    }
  }
  if (start < 0) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    const match = /^(#{1,6})\s+/.exec(lines[i]);
    if (match && match[1].length <= level) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join('\n').trim();
}

function searchMarkdown(markdown, query, limit) {
  const terms = normalize(query).split(/\s+/).filter(Boolean);
  const lines = markdown.split(/\r?\n/);
  const hits = [];
  let currentHeading = '';
  for (let i = 0; i < lines.length; i += 1) {
    const heading = /^(#{1,6})\s+(.+?)\s*$/.exec(lines[i]);
    if (heading) currentHeading = heading[2];
    const hay = normalize(lines[i]);
    const score = terms.reduce((n, t) => n + (hay.includes(t) ? 1 : 0), 0);
    if (!score) continue;
    const from = Math.max(0, i - 2);
    const to = Math.min(lines.length, i + 4);
    hits.push({
      score,
      line: i + 1,
      heading: currentHeading,
      excerpt: lines.slice(from, to).join('\n').trim(),
    });
  }
  hits.sort((a, b) => b.score - a.score || a.line - b.line);
  return hits.slice(0, limit);
}

function openapiEndpointExcerpt(yaml, method, path) {
  const lines = yaml.split(/\r?\n/);
  const pathLine = `  ${path}:`;
  const startPath = lines.findIndex(line => line === pathLine);
  if (startPath < 0) return null;
  const normalizedMethod = normalize(method);
  const methodLine = `    ${normalizedMethod}:`;
  let methodStart = -1;
  for (let i = startPath + 1; i < lines.length; i += 1) {
    if (/^  \/.+:\s*$/.test(lines[i])) break;
    if (lines[i] === methodLine) {
      methodStart = i;
      break;
    }
  }
  if (methodStart < 0) return null;
  let end = lines.length;
  for (let i = methodStart + 1; i < lines.length; i += 1) {
    if (/^  \/.+:\s*$/.test(lines[i]) || /^    [a-z]+:\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(methodStart, end).join('\n').trim();
}

const examples = {
  curl: {
    authorization_code: `curl --fail-with-body https://auth.example.com/oauth/token \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data-urlencode 'grant_type=authorization_code' \\\n  --data-urlencode 'client_id=CLIENT_ID' \\\n  --data-urlencode 'code=AUTHORIZATION_CODE' \\\n  --data-urlencode 'redirect_uri=https://app.example.com/oauth/callback' \\\n  --data-urlencode 'code_verifier=PKCE_VERIFIER'`,
    userinfo: `curl --fail-with-body https://auth.example.com/oauth/userinfo \\\n  -H 'Authorization: Bearer ACCESS_TOKEN'`,
    client_credentials: `curl --fail-with-body https://auth.example.com/oauth/token \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data-urlencode 'grant_type=client_credentials' \\\n  --data-urlencode 'client_id=CLIENT_ID' \\\n  --data-urlencode 'client_secret=CLIENT_SECRET' \\\n  --data-urlencode 'scope=api:read' \\\n  --data-urlencode 'resource=https://api.example.com'`,
  },
  javascript: {
    authorization_code: `import { OpenProofIdentity } from "@openproof/identity";\n\nconst identity = new OpenProofIdentity({\n  issuer: "https://auth.example.com",\n  clientId: "CLIENT_ID",\n  redirectUri: "https://app.example.com/oauth/callback",\n  scopes: ["openid", "profile", "offline_access"]\n});\n\nawait identity.login();`,
    userinfo: `const tokens = await identity.handleCallback();\nconst profile = await identity.userInfo(tokens.access_token);`,
  },
  node: {
    authorization_code: `const body = new URLSearchParams({\n  grant_type: "authorization_code",\n  client_id: process.env.OPENPROOF_CLIENT_ID,\n  code,\n  redirect_uri: "https://app.example.com/oauth/callback",\n  code_verifier: verifier\n});\n\nconst response = await fetch("https://auth.example.com/oauth/token", {\n  method: "POST",\n  headers: { "content-type": "application/x-www-form-urlencoded" },\n  body\n});\n\nif (!response.ok) throw new Error("OpenProof token exchange failed");\nconst tokens = await response.json();`,
  },
  php: {
    authorization_code: `$payload = http_build_query([\n  'grant_type' => 'authorization_code',\n  'client_id' => getenv('OPENPROOF_CLIENT_ID'),\n  'code' => $_GET['code'],\n  'redirect_uri' => 'https://app.example.com/oauth/callback',\n  'code_verifier' => $_SESSION['openproof_pkce_verifier'],\n]);\n\n$curl = curl_init('https://auth.example.com/oauth/token');\ncurl_setopt_array($curl, [\n  CURLOPT_POST => true,\n  CURLOPT_POSTFIELDS => $payload,\n  CURLOPT_RETURNTRANSFER => true,\n  CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],\n]);`,
  },
  cpp: {
    authorization_code: `import openproof.sdk;\n\nauto config = openproof::sdk::ClientConfig::create(\n    "https://auth.example.com",\n    "CLIENT_ID",\n    "http://127.0.0.1:49152/callback",\n    {"openid", "profile", "offline_access"});\n\nopenproof::sdk::IdentityClient client{std::move(config).value()};\nauto login = client.beginLogin();\nstd::cout << login->authorizationUrl() << '\\\\n';`,
  },
};

const checklists = {
  install: [
    'Supported Ubuntu/Debian host and architecture',
    'Stable identity domain chosen',
    'PostgreSQL local/external decision',
    'Verification delivery mode chosen',
    'Provider credentials only for providers being enabled now',
    'Gateway upstream known or defaults accepted',
    'TLS/ingress strategy chosen',
    'openproof status and openproof doctor pass',
  ],
  developer: [
    'Application registered',
    'Correct client kind selected',
    'Exact redirect URI registered',
    'Authorization Code + PKCE S256 implemented',
    'state and returned issuer validated',
    'ID-token signature and claims validated against JWKS',
    'Access token audience/scope authorized',
    'Refresh-token rotation persisted atomically',
  ],
  production: [
    'Real DNS and trusted HTTPS',
    'Real SMTP/webhook delivery',
    'Database backup and restore drill',
    'Owner protected with MFA',
    'Provider callbacks use production origin',
    'Secrets excluded from source control and logs',
    'Readiness monitoring enabled',
    'Rotation/incident procedures documented',
  ],
};

function buildMcp() {
  const mcp = new McpServer({ name: 'OpenProof Documentation', version: VERSION });

  mcp.registerTool('search_openproof_docs', {
    title: 'Search OpenProof docs',
    description: 'Search the public OpenProof deployment and developer handbook. Returns short excerpts with section headings and line numbers.',
    inputSchema: z.object({
      query: z.string().min(2).max(300),
      limit: z.number().int().min(1).max(20).default(8),
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ query, limit }) => {
    const markdown = await handbookText();
    const hits = searchMarkdown(markdown, query, limit);
    return result(JSON.stringify({ query, hits, handbook: URLS.handbook }, null, 2));
  });

  mcp.registerTool('get_openproof_guide', {
    title: 'Get OpenProof guide',
    description: 'Return a focused public guide section for install, deploy, OAuth/OIDC, language integration, API security, accounts, providers, production, troubleshooting or AI/MCP.',
    inputSchema: z.object({
      topic: z.enum(['install','deploy','oauth','javascript','node','php','cpp','api','accounts','providers','production','troubleshooting','ai']),
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ topic }) => {
    const markdown = await handbookText();
    const headings = {
      install: 'Part I - Deploy and configure',
      deploy: 'Part I - Deploy and configure',
      oauth: 'Developer mental model',
      javascript: 'JavaScript/browser SDK',
      node: 'Node.js integration',
      php: 'PHP integration',
      cpp: 'C++ integration',
      api: 'Register a protected API resource',
      accounts: 'Account signup and verification',
      providers: 'External sign-in providers',
      production: 'Production checklist',
      troubleshooting: 'Part IV - Troubleshooting',
      ai: 'Part III - LLM and MCP integration',
    };
    const section = sectionFromMarkdown(markdown, headings[topic]) ?? markdown;
    return result(section + `\n\nCanonical: ${URLS.handbook}`);
  });

  mcp.registerTool('get_openproof_endpoint', {
    title: 'Get OpenProof endpoint',
    description: 'Look up a method/path in the public OpenAPI 3.1 contract and return that operation block.',
    inputSchema: z.object({
      method: z.enum(['get','post','put','patch','delete','head','options']),
      path: z.string().startsWith('/').max(220),
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ method, path }) => {
    const yaml = await openapiText();
    const excerpt = openapiEndpointExcerpt(yaml, method, path);
    if (!excerpt) {
      return result(JSON.stringify({ found: false, method, path, openapi: URLS.openapi }, null, 2), { isError: true });
    }
    return result(`# ${method.toUpperCase()} ${path}\n\n${excerpt}\n\nOpenAPI: ${URLS.openapi}`);
  });

  mcp.registerTool('get_openproof_example', {
    title: 'Get OpenProof example',
    description: 'Return a documented OpenProof integration example for a language and use case.',
    inputSchema: z.object({
      language: z.enum(['curl','javascript','node','php','cpp']),
      use_case: z.enum(['authorization_code','userinfo','client_credentials']),
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ language, use_case }) => {
    const code = examples[language]?.[use_case];
    if (!code) {
      return result(JSON.stringify({
        found: false,
        language,
        use_case,
        note: 'That language/use-case combination is not in the curated example set. Use the handbook or OpenAPI contract.',
        develop: URLS.develop,
      }, null, 2), { isError: true });
    }
    return result(`${code}\n\nDeveloper guide: ${URLS.develop}`);
  });

  mcp.registerTool('get_openproof_checklist', {
    title: 'Get OpenProof checklist',
    description: 'Return an installation, developer-integration or production-readiness checklist.',
    inputSchema: z.object({
      kind: z.enum(['install','developer','production']),
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ kind }) => result(JSON.stringify({
    kind,
    checklist: checklists[kind],
    handbook: URLS.handbook,
  }, null, 2)));

  mcp.registerTool('get_openproof_sources', {
    title: 'Get OpenProof sources',
    description: 'Return the canonical public OpenProof documentation, LLM and OpenAPI entry points.',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async () => {
    const openproofRelease = await currentOpenProofVersion();
    return result(JSON.stringify({ openproofRelease, docsMcpVersion: VERSION, ...URLS }, null, 2));
  });

  return mcp;
}

let windowStarted = Date.now();
let requests = 0;
function rateLimited() {
  const now = Date.now();
  if (now - windowStarted >= 60_000) {
    windowStarted = now;
    requests = 0;
  }
  requests += 1;
  return requests > 240;
}

const httpServer = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    if (url.pathname === '/health') {
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
      });
      const openproofRelease = await currentOpenProofVersion();
      res.end(JSON.stringify({
        ok: true,
        service: 'openproof-docs-mcp',
        version: VERSION,
        openproofRelease,
      }));
      return;
    }
    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }
    if (rateLimited()) {
      res.writeHead(429, {
        'content-type': 'application/json; charset=utf-8',
        'retry-after': '60',
      });
      res.end(JSON.stringify({ error: 'rate_limited' }));
      return;
    }
    const contentLength = Number(req.headers['content-length'] ?? 0);
    if (Number.isFinite(contentLength) && contentLength > 1_000_000) {
      res.writeHead(413, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'request_too_large' }));
      return;
    }

    const mcp = buildMcp();
    const transport = new StreamableHTTPServerTransport();
    await mcp.connect(transport);
    res.once('close', () => void mcp.close().catch(() => undefined));
    await transport.handleRequest(req, res);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!res.headersSent) {
      res.writeHead(500, { 'content-type': 'application/json; charset=utf-8' });
    }
    if (!res.writableEnded) {
      res.end(JSON.stringify({ error: 'internal_error', message }));
    }
  }
});

httpServer.listen(PORT, HOST, () => {
  console.log(JSON.stringify({
    event: 'listening',
    service: 'openproof-docs-mcp',
    version: VERSION,
    host: HOST,
    port: PORT,
    endpoint: '/mcp',
  }));
});
