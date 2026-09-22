# OpenProof public documentation MCP

This directory contains the source for the public, read-only documentation MCP
served at:

```text
https://docs.genyleap.com/openproof/mcp
```

It is deliberately separate from the OpenProof runtime/admin plane. The server
reads only public documentation and the public OpenAPI contract; it does not
read `/etc/openproof`, PostgreSQL credentials, provider/client secrets, live
sessions, users, tokens, private keys, or service logs.

## Run locally

```bash
npm ci
npm run check
npm start
```

Defaults:

```text
host      127.0.0.1
port      8792
handbook  ../../docs/HANDBOOK.md
openapi   ../../docs/openapi.yaml
```

Optional environment overrides:

```text
OPENPROOF_DOCS_MCP_HOST
OPENPROOF_DOCS_MCP_PORT
OPENPROOF_DOCS_MCP_HANDBOOK
OPENPROOF_DOCS_MCP_OPENAPI
```

The HTTP transport is at `/mcp`; `/health` is a small deployment health
endpoint.

## Tools

- `search_openproof_docs`
- `get_openproof_guide`
- `get_openproof_endpoint`
- `get_openproof_example`
- `get_openproof_checklist`
- `get_openproof_sources`

All MCP tools are annotated read-only, non-destructive and idempotent.

For the trust boundary and recommended LLM/RAG source ordering, see
[`docs/AI_AND_MCP.md`](../../docs/AI_AND_MCP.md).
