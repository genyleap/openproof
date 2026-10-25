import fs from "node:fs";
import path from "node:path";

const root = path.resolve(process.cwd(), "src");
const patterns = {
  coroutine: /\b(?:co_await|co_return|co_yield)\b/g,
  blockingSql: /\bPQexec(?:Params)?\s*\(/g,
  connectionWait: /\b(?:wait_for|wait_until)\s*\(/g,
  synchronousHttp: /\b(?:http|beastHttp)::(?:read|write)\s*\(/g,
  asynchronousHttp: /\b(?:async_read|async_write|async_accept|async_connect)\s*\(/g,
  synchronousDNS: /\b(?:resolver\.)resolve\s*\(/g,
  cryptoHash: /\b(?:crypto_pwhash|EVP_Digest|sodium_crypto_pwhash)\b/g,
  threads: /\bstd::(?:thread|jthread|async)\b/g,
  mutex: /\bstd::(?:mutex|shared_mutex|condition_variable)\b/g,
};
const total = {files: 0, lines: 0};
const modules = {};
const suspects = [];
function scan(directory) {
  for (const item of fs.readdirSync(directory, {withFileTypes: true})) {
    const file = path.join(directory, item.name);
    if (item.isDirectory()) {scan(file); continue;}
    if (!/\.(?:cpp|cppm|h|hpp)$/.test(file)) continue;
    const source = fs.readFileSync(file, "utf8");
    const relative = path.relative(root,file);
    const moduleName = relative.split(path.sep)[0];
    total.files++; total.lines += source.split("\n").length;
    const counts = {};
    for (const [key, pattern] of Object.entries(patterns)) {
      const count = [...source.matchAll(pattern)].length;
      counts[key] = count; total[key] = (total[key] ?? 0) + count;
    }
    const group = modules[moduleName] ??= {files:0,lines:0};
    group.files++;group.lines += source.split("\n").length;
    for (const [key,count] of Object.entries(counts)) group[key] = (group[key]??0)+count;
    if(counts.blockingSql+counts.synchronousHttp+counts.synchronousDNS+counts.connectionWait>0)
      suspects.push({file:relative,...counts});
  }
}
scan(root);
suspects.sort((a,b)=> (b.blockingSql+b.synchronousHttp+b.synchronousDNS+b.connectionWait) - (a.blockingSql+a.synchronousHttp+a.synchronousDNS+a.connectionWait));
console.log(JSON.stringify({total,modules,suspects:suspects.slice(0,55)},null,2));
