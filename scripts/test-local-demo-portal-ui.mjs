import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("./local-demo-portal-v3.js", import.meta.url), "utf8");
const catalog = [
  {method:"GET",path:"/health/ready",operation_id:"readiness",tag:"Health",description:"",responses:["200"],parameters:[]},
  {method:"GET",path:"/account/profile",operation_id:"getProfile",tag:"Account",description:"",responses:["200","401"],parameters:[]},
  {method:"PATCH",path:"/account/profile",operation_id:"updateProfile",tag:"Account",description:"",responses:["200","401"],parameters:[]},
  {method:"PUT",path:"/account/profile",operation_id:"replaceProfileFields",tag:"Account",description:"",responses:["200","401"],parameters:[]},
  {method:"POST",path:"/auth/web3/start",operation_id:"beginWeb3Login",tag:"Federation",description:"",responses:["200","400"],parameters:[]},
  {method:"GET",path:"/oauth/authorize",operation_id:"authorize",tag:"OAuth",description:"",responses:["302","400"],parameters:[
    {name:"response_type",in:"query",required:true,type:"string",example:"code",description:""},
    {name:"client_id",in:"query",required:true,type:"string",example:"",description:""},
    {name:"redirect_uri",in:"query",required:true,type:"string",example:"",description:""},
    {name:"scope",in:"query",required:true,type:"string",example:"",description:""},
    {name:"state",in:"query",required:true,type:"string",example:"",description:""},
  ]},
  {method:"DELETE",path:"/account/passkeys/{credential_id}",operation_id:"removePasskey",tag:"Passkeys",description:"",responses:["200","401"],parameters:[
    {name:"credential_id",in:"path",required:true,type:"string",example:"",description:""},
  ]},
];

const listeners = {};
const app = {
  innerHTML: "",
  addEventListener(type, handler) { (listeners[type] ??= []).push(handler); },
  querySelector() { return {lastChild:{textContent:""}}; },
};
let toast;
const document = {
  documentElement: {lang:"",dir:""},
  body: {append(node) { toast = node; }},
  getElementById(id) {
    if (id === "app") return app;
    if (id === "openproof-demo") return {textContent:'{"email":"rider@example.test","password":"correct horse battery staple"}'};
    if (id === "openproof-context") return {textContent:'{"base_url":"https://127.0.0.1:50114"}'};
    return null;
  },
  querySelector(selector) { return selector === ".toast" ? toast ?? null : null; },
  createElement() { return {className:"",innerHTML:"",classList:{toggle(){}}}; },
};

const profile = {identity_id:"opi_test",display_name:"Test Rider",preferred_username:"test-rider",email:"rider@example.test",email_verified:true,phone_number:null,phone_number_verified:false,locale:"en-US"};
const jsonResponse = (value) => ({ok:true,status:200,async json(){return value;}});
async function fetch(url, options = {}) {
  if (url === "/api/catalog") return jsonResponse({operations:catalog});
  if (url === "/api/messages") return jsonResponse({messages:[]});
  if (url === "/api/session/status") return jsonResponse({authenticated:false,status:401,profile:null});
  if (url === "/api/request") {
    const input = JSON.parse(options.body);
    const authenticated = input.credential_mode === "bearer" && /^Bearer test-token$/.test(input.headers?.authorization ?? "");
    const status = input.path.startsWith("/account/profile") && !authenticated ? 401 : 200;
    const body = status === 200 ? profile : {error:{code:"AUTHENTICATION_REQUIRED",message:"Authentication is required."}};
    return jsonResponse({status,duration_ms:4.2,headers:{"content-type":"application/json","x-request-id":"test"},body:JSON.stringify(body)});
  }
  return jsonResponse({});
}

const context = vm.createContext({
  console, document, fetch, URL, URLSearchParams,
  localStorage:{getItem(){return "en";},setItem(){}},
  navigator:{clipboard:{async writeText(){}}},
  setTimeout(){return 0;},
  window:{scrollTo(){}},
});
vm.runInContext(source, context, {filename:"local-demo-portal-v3.js"});
await new Promise((resolve) => setImmediate(resolve));
await new Promise((resolve) => setImmediate(resolve));

function actionTarget(action, data = {}) {
  return {
    dataset:{action,...data},
    closest(selector) { return selector === "[data-action]" ? this : null; },
  };
}
async function click(action, data = {}) {
  const event = {target:actionTarget(action, data),stopPropagation(){}};
  for (const handler of listeners.click) await handler(event);
}
function input(dataset, value) {
  for (const handler of listeners.input) handler({target:{dataset,value}});
}

await click("page", {page:"explorer"});
await click("preset", {method:"GET",path:"/account/profile"});
assert.match(app.innerHTML, /Which profile is returned\?/);
assert.match(app.innerHTML, /No identity signed in/);
assert.match(app.innerHTML, /User lookup: not supported/);
assert.doesNotMatch(app.innerHTML, /<textarea[^>]*disabled/);
assert.match(app.innerHTML, /data-method="POST" disabled/);

await click("send-request");
assert.match(app.innerHTML, /HTTP 401/);
assert.match(app.innerHTML, /AUTHENTICATION_REQUIRED/);

await click("auth-mode", {mode:"bearer"});
await click("send-request");
assert.match(app.innerHTML, /An access token is required/);
input({bind:"explorer.auth"}, "test-token");
await click("send-request");
assert.match(app.innerHTML, /HTTP 200/);
assert.match(app.innerHTML, /Test Rider/);

await click("pick-operation", {method:"GET",path:"/oauth/authorize"});
assert.match(app.innerHTML, /Path &amp; query parameters|Path & query parameters/);
assert.match(app.innerHTML, /response_type/);
assert.match(app.innerHTML, /\/oauth\/authorize\?response_type=code/);

await click("pick-operation", {method:"DELETE",path:"/account/passkeys/{credential_id}"});
assert.match(app.innerHTML, /CREDENTIAL_ID/);
assert.match(app.innerHTML, /\/account\/passkeys\/CREDENTIAL_ID/);

for (const [language, marker, filename] of [
  ["cpp_stl", /libcurl as the HTTP transport/, /example_stl\.cpp/],
  ["cpp_qt", /QNetworkAccessManager/, /example_qt\.cpp/],
  ["cpp_boost", /Boost 1\.82\+ HTTPS example/, /example_boost\.cpp/],
]) {
  await click("code-language", {language});
  assert.match(app.innerHTML, marker);
  assert.match(app.innerHTML, filename);
}
assert.match(app.innerHTML, /C\+\+ \/ STL/);
assert.match(app.innerHTML, /C\+\+ \/ Qt/);
assert.match(app.innerHTML, /C\+\+ \/ Boost/);

await click("code-language", {language:"web3"});
assert.match(app.innerHTML, /ethereum-wallet/);
assert.match(app.innerHTML, /provider:.*farcaster/);

await click("language");
assert.equal(document.documentElement.dir, "rtl");
assert.match(app.innerHTML, /کدام پروفایل|API Explorer و کد/);

for (const [page, marker] of [["guide","راهنمای معماری"],["journey","آزمایشگاه هویت"],["farcaster","آزمایشگاه Farcaster"],["reference","مرجع کامل API"],["inbox","صندوق تحویل محلی"],["explorer","API Explorer و کد"]]) {
  await click("page", {page});
  assert.match(app.innerHTML, new RegExp(marker));
  assert.doesNotMatch(app.innerHTML, /undefined|\[object Object\]/);
}

console.log("OpenProof portal UI behavior test passed.");
