import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const cwd = dirname(fileURLToPath(import.meta.url));
const port = 26000 + (process.pid % 17000);
const endpoint = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, [join(cwd, 'server.mjs')], {
  cwd, env: { ...process.env, OPENPROOF_DOCS_MCP_HOST: '127.0.0.1',
    OPENPROOF_DOCS_MCP_PORT: String(port) },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let stderr = '';
server.stderr.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-1000); });
let client;
try {
  let ready = false;
  for (let attempt = 0; attempt < 45; ++attempt) {
    if (server.exitCode !== null) throw new Error('Docs MCP server exited before readiness');
    try {
      const response = await fetch(endpoint + '/health', { signal: AbortSignal.timeout(600) });
      const health = await response.json();
      if (response.ok && health.ok === true && health.openproofRelease === '1.1.0-rc6') {
        ready = true;
        break;
      }
    } catch {}
    await sleep(150);
  }
  assert.ok(ready, 'docs server must report RC6 health');
  client = new Client({name: 'openproof-docs-regression', version: '1.0.0'});
  const transport = new StreamableHTTPClientTransport(new URL(endpoint + '/mcp'));
  await client.connect(transport);
  const tools = await client.listTools();
  const expected = [
    'search_openproof_docs', 'get_openproof_guide', 'get_openproof_endpoint',
    'get_openproof_example', 'get_openproof_checklist', 'get_openproof_sources'
  ];
  assert.deepEqual(tools.tools.map(x => x.name).sort(), expected.sort());
  for (const tool of tools.tools) {
    assert.equal(tool.annotations?.readOnlyHint, true);
    assert.equal(tool.annotations?.destructiveHint, false);
  }
  const sources = await client.callTool({name:'get_openproof_sources',arguments:{}});
  assert.equal(sources.isError, undefined);
  assert.equal(JSON.parse(sources.content[0].text).openproofRelease, '1.1.0-rc6');
  const result = await client.callTool({
    name:'get_openproof_endpoint', arguments:{method:'get',path:'/account/sessions'}});
  assert.notEqual(result.isError,true);
  assert.match(result.content[0].text,/\/account\/sessions/);
  const missing = await client.callTool({
    name:'get_openproof_endpoint', arguments:{method:'get',path:'/definitely-not-an-endpoint'}});
  assert.equal(missing.isError,true);
  console.log('Docs MCP integration passed: health, transport, six tools, read-only annotations, API lookup, errors');
} catch (error) {
  console.error('Docs MCP integration failed:',error?.message||String(error));
  if(stderr) console.error('Isolated server diagnostic:',stderr);
  process.exitCode=1;
} finally {
  if(client) await client.close().catch(()=>{});
  server.kill('SIGTERM');
  await Promise.race([new Promise(resolve=>server.once('exit',resolve)),sleep(2000)]);
  if(server.exitCode===null) server.kill('SIGKILL');
}
