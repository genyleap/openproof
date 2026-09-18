(() => {
  "use strict";
  const base = {
    setPanel: window.setPanel,
    renderReference: window.renderReference,
    operationExplanation: window.operationExplanation,
    authenticationHint: window.authenticationHint,
    messageCard: window.messageCard,
    updateCode: window.updateCode,
    showResponse: window.showResponse,
    toast: window.toast,
  };
  let locale = localStorage.getItem("openproof.portal.locale") === "en" ? "en" : "fa";
  let selectedOperation = null;
  const isEn = () => locale === "en";
  const t = (fa, en) => isEn() ? en : fa;
  const icon = name => `<span class="ms" aria-hidden="true">${name}</span>`;

  const panelCopy = {
    fa: {
      guide: ["راهنمای شروع توسعه", "از انتخاب روش اتصال تا اولین کاربر و اولین access token."],
      reference: ["مرجع کامل API", "همه operationهای قرارداد OpenAPI، قابل جستجو، بررسی و اجرا."],
      explorer: ["API Explorer و مثال کد", "درخواست واقعی بفرست و معادل آن را برای زبان خودت بردار."],
      inbox: ["صندوق verification آزمایشی", "پیام‌های واقعی delivery webhook را ببین و مصرف کن."],
    },
    en: {
      guide: ["Developer quickstart", "From choosing an integration path to your first user and access token."],
      reference: ["Complete API reference", "Search, inspect and run every operation in the OpenAPI contract."],
      explorer: ["API Explorer & code", "Send a real request, inspect the response and copy production-ready code."],
      inbox: ["Verification inbox", "Inspect and consume real delivery-webhook messages in the local environment."],
    },
  };
  const guideCopy = {
    fa: {
      heroTitle: "OpenProof هسته‌ی هویت محصول شماست",
      heroBody: "محصول وب، موبایل، دسکتاپ، backend یا dApp به OpenProof متصل می‌شود؛ OpenProof ثبت‌نام، احراز هویت، session، OAuth/OIDC، Web3، مدیریت دسترسی و trust را مدیریت می‌کند. برای بیشتر محصولات، مسیر استاندارد اتصال <b>Authorization Code + PKCE</b> است.",
      pathTitle: "کدام مسیر برای من مناسب است؟", pathSub: "ابتدا نوع مصرف‌کننده را انتخاب کن؛ هر کارت یک مثال قابل اجرا باز می‌کند.",
      choices: [
        ["ثبت‌نام و حساب کاربری", "برای صفحه account خود OpenProof: signup، تأیید ایمیل، login دومرحله‌ای و profile با cookie امن."],
        ["وب، موبایل و دسکتاپ", "محصول مستقل با OAuth/OIDC و PKCE؛ محصول access token می‌گیرد و session داخلی OpenProof را کپی نمی‌کند."],
        ["Backend و سرویس‌ها", "Machine-to-machine با client_credentials، scope و audience محدود؛ بدون session انسانی و refresh token."],
        ["Web3 و کیف پول", "دریافت پیام SIWE از OpenProof، امضای دقیق همان پیام در wallet و تکمیل challenge بدون تحویل private key."],
      ],
      flowTitle: "جریان استاندارد یک محصول", flowSub: "این جداسازی باعث می‌شود هر زبان یا framework فقط استاندارد HTTP/OIDC را مصرف کند.",
      flows: [["1. ثبت Client", "در admin یک application و client با redirect URI دقیق بساز."],["2. Authorization + PKCE", "verifier/state/nonce بساز و کاربر را به OpenProof هدایت کن."],["3. Token Exchange", "code یک‌بارمصرف را با verifier به access/refresh/ID token تبدیل کن."],["4. API Authorization", "در backend، audience/scope و وضعیت token را validate یا introspect کن."]],
      conceptTitle: "شش مفهوم که باید دقیق بدانی",
      concepts: [["Session Cookie", "برای صفحات account/admin خود OpenProof است. مرورگر یا cookie jar آن را نگه می‌دارد؛ آن را به دامنه محصولت کپی نکن."],["Access Token", "اعتبار محصول و API است. backend باید audience، scope و active بودن آن را بررسی کند."],["PKCE + State + Nonce", "PKCE جلوی سرقت code، state جلوی CSRF و nonce جلوی replay در ID Token را می‌گیرد. حذف هیچ‌کدام مجاز نیست."],["Delivery Webhook", "OpenProof secret تأیید را به adapter شما می‌دهد؛ adapter آن را با ایمیل/SMS می‌فرستد. Inbox محلی نمونه توسعه آن است."],["Web3 Proof", "OpenProof فقط signature را می‌گیرد و private key هرگز وارد هسته نمی‌شود. message، domain، nonce و chain به ceremony متصل‌اند."],["SDK یا HTTP مستقیم", "SDK خطاهای امنیتی PKCE/OIDC را کم می‌کند؛ هر زبان دیگری می‌تواند قرارداد استاندارد HTTP و OpenAPI را مستقیم مصرف کند."]],
    },
    en: {
      heroTitle: "OpenProof is your product's identity core",
      heroBody: "Your web, mobile, desktop, backend or dApp connects to OpenProof. It manages registration, authentication, sessions, OAuth/OIDC, Web3, access control and trust. For most products, the standard integration is <b>Authorization Code + PKCE</b>.",
      pathTitle: "Which path should I use?", pathSub: "Choose your consumer type first. Every card opens a runnable example.",
      choices: [["Registration & accounts", "Use OpenProof account flows for signup, email verification, two-step login and profiles with secure cookies."],["Web, mobile & desktop", "Use OAuth/OIDC with PKCE. Your product receives tokens and never copies OpenProof's internal session."],["Backend & services", "Use machine-to-machine client_credentials with a narrow scope and audience; no human session or refresh token."],["Web3 & wallets", "Request the SIWE message, sign that exact message in the wallet and complete the challenge without exposing a private key."]],
      flowTitle: "A product's standard flow", flowSub: "This separation lets every language and framework consume the same HTTP/OIDC standards.",
      flows: [["1. Register a client", "Create an application and client in admin with an exact redirect URI."],["2. Authorization + PKCE", "Create verifier, state and nonce, then redirect the user to OpenProof."],["3. Token exchange", "Exchange the one-time code plus verifier for access, refresh and ID tokens."],["4. API authorization", "Validate or introspect token audience, scope and active state in your backend."]],
      conceptTitle: "Six concepts to understand",
      concepts: [["Session Cookie", "Only for OpenProof account/admin pages. Keep it in the browser or cookie jar; never copy it to your product domain."],["Access Token", "The API credential. Your backend must verify its audience, scope and active state."],["PKCE + State + Nonce", "PKCE protects the code, state protects against CSRF and nonce prevents ID Token replay. Keep all three."],["Delivery Webhook", "OpenProof gives a verification secret to your adapter; the adapter sends email/SMS. The local inbox is the development implementation."],["Web3 Proof", "OpenProof receives only a signature. The private key never enters the identity core; message, domain, nonce and chain bind the ceremony."],["SDK or direct HTTP", "SDKs reduce OIDC/PKCE mistakes, while every other language can consume the standard HTTP and OpenAPI contract directly."]],
    },
  };
  const endpointHelpEn = {
    "/health/live":"Process liveness probe.", "/health/ready":"Checks service and PostgreSQL readiness before accepting traffic.", "/metrics":"Private Prometheus metrics; requires the operations metrics bearer.",
    "/account/signup":"Creates a pending identity and sends signup_email to the delivery webhook.", "/account/email/verify":"Consumes verification_id and its one-time secret to activate the account.", "/account/email/resend":"Resends verification without disclosing whether an account exists.", "/account/email/change":"Starts an email change for the current session.", "/account/email/change/verify":"Completes the email change using the delivered proof.", "/account/phone":"Starts phone verification for the current session.", "/account/phone/verify":"Consumes the phone secret and records a verified phone claim.", "/account/password/forgot":"Requests password recovery without account enumeration.", "/account/password/reset":"Consumes recovery proof once and replaces the credential.", "/account/profile":"Reads or patches the current session identity profile.",
    "/auth/login":"Login step one: issues a transaction, challenge and pre-auth cookies; login is not complete yet.", "/auth/mfa/verify":"Login step two: verifies password and optional TOTP, then issues a secure session.", "/auth/session/rotate":"Atomically rotates the current session identifier.", "/auth/logout":"Revokes only the current session.", "/auth/logout-all":"Revokes every session for the identity.", "/auth/providers":"Lists enabled social, enterprise, passkey and Web3 providers.", "/auth/web3/start":"Creates a wallet-bound message and one-time nonce; sign only the returned message.", "/auth/web3/complete":"Verifies the wallet proof and issues a session.",
    "/.well-known/openid-configuration":"Publishes the issuer's OAuth/OIDC endpoints and capabilities.", "/.well-known/jwks.json":"Publishes public keys for ID Token signature validation.", "/oauth/authorize":"Starts Authorization Code + PKCE and redirects only to a registered URI.", "/oauth/token":"Exchanges authorization codes, refresh tokens, client credentials or subject tokens.", "/oauth/userinfo":"Returns standard user claims for a suitable access token.", "/oauth/revoke":"Revokes an access or refresh token for its owning client.", "/oauth/introspect":"Returns active state, scope, audience and subject to a trusted backend.", "/oauth/par":"Registers authorization parameters server-side and returns a short-lived request_uri.",
    "/evidence/challenge":"Issues a one-time challenge for an evidence provider.", "/evidence/verify":"Validates provider proof against its challenge and policy.", "/evidence":"Lists verified evidence for the current identity.", "/trust":"Returns the trust decision and assurance derived from evidence.",
    "/admin/applications":"Creates or lists logical products; OAuth clients belong to an application.", "/admin/clients":"Registers or lists OAuth clients, redirect URIs and allowed scopes.", "/admin/resources":"Registers protected API audiences and scopes.", "/admin/service-identities":"Manages machine identity permissions for client_credentials."
  };
  const authEn = path => {
    if (["/health/live","/health/ready","/account/signup","/account/email/verify","/account/email/resend","/account/password/forgot","/account/password/reset","/.well-known/openid-configuration","/.well-known/jwks.json","/auth/login","/auth/providers"].includes(path)) return "Public endpoint. Multi-step operations may issue a temporary cookie.";
    if (path === "/metrics") return "Dedicated metrics bearer; a user access token is not accepted.";
    if (path === "/auth/mfa/verify" || /^\/auth\/(web3|ldap|passkey)\//.test(path)) return "Cookie-bound ceremony. Preserve the cookie jar from start through completion.";
    if (["/oauth/token","/oauth/introspect","/oauth/revoke","/oauth/par"].includes(path)) return "OAuth client authentication. Public clients send client_id; confidential clients also send their secret in the form body.";
    if (path === "/oauth/userinfo" || path.startsWith("/evidence") || path === "/trust") return "Authorization: Bearer ACCESS_TOKEN, or an allowed session as defined by OpenAPI.";
    if (path.startsWith("/admin/")) return "Owner/admin session with the required role and assurance; sensitive operations normally require IAL2.";
    if (path.startsWith("/scim/")) return "Tenant-specific SCIM bearer. Never mix it with user access tokens.";
    if (path.startsWith("/account/") || path.startsWith("/auth/")) return "OpenProof session cookie or an allowed bearer. Sending both is intentionally rejected as ambiguous.";
    return "Inspect this operation's security requirement in OpenAPI.";
  };

  const escaped = value => String(value).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[ch]);
  function highlightLine(line, language) {
    const keywords = language === "php" ? "php|function|new|true|false|null|if|else|throw|return|const" : language === "cpp" ? "include|auto|const|QString|QUrl|QNetworkRequest|QNetworkReply|QObject|if|else|throw|return|true|false|nullptr" : "const|let|var|await|async|function|new|true|false|null|undefined|if|else|throw|return|import|from";
    const pattern = new RegExp(`(//.*$|#(?!include\\b).*$)|("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*')|(\\b(?:${keywords})\\b)|(\\$[A-Za-z_][\\w]*|\\b[A-Za-z_][\\w]*(?=\\s*\\())|(\\b\\d+(?:\\.\\d+)?\\b)`, "gm");
    let html = "", cursor = 0;
    for (const match of line.matchAll(pattern)) {
      html += escaped(line.slice(cursor, match.index));
      const klass = match[1] ? "comment" : match[2] ? "string" : match[3] ? "keyword" : match[4] ? (match[4].startsWith("$") ? "variable" : "function") : "number";
      html += `<span class="tok-${klass}">${escaped(match[0])}</span>`;
      cursor = match.index + match[0].length;
    }
    return html + escaped(line.slice(cursor));
  }
  function renderEditor(element, code, language="javascript") {
    const lines = String(code || " ").split("\n");
    element.dataset.rawCode = code;
    element.innerHTML = `<ol class="code-lines">${lines.map(line => `<li>${highlightLine(line || " ", language)}</li>`).join("")}</ol>`;
  }
  function addChrome() {
    document.querySelectorAll(".response-head,.code-head").forEach(head => {
      if (head.querySelector(".traffic")) return;
      const chrome = document.createElement("div"); chrome.className = "editor-chrome";
      chrome.innerHTML = `<span class="traffic"><i></i><i></i><i></i></span><span class="editor-file">${head.classList.contains("response-head") ? "response.json" : "openproof-example"}</span>`;
      head.prepend(chrome);
    });
  }
  window.updateCode = function () {
    base.updateCode();
    renderEditor(document.getElementById("codeOutput"), document.getElementById("codeOutput").textContent, activeLanguage || "javascript");
    if (isEn()) {
      document.getElementById("codeNote").textContent = ({
        curl:"Keep the same cookie file from start through completion. For local TLS, pass the generated CA with --cacert.",
        javascript:"In browsers, use Authorization Code + PKCE or a same-site BFF. Configure deployment CORS and cookie policy deliberately.",
        php:"Keep the cookie jar in a protected path and read client_secret only from the backend secret store.",
        cpp:"Keep QNetworkAccessManager alive so its cookie jar survives every login step. Production connections must use HTTPS.",
        web3:"Sign only the message issued by OpenProof. Never send a private key, seed phrase or hand-written message.",
      })[activeLanguage];
    }
  };
  window.showResponse = function (result) {
    base.showResponse(result);
    const output = document.getElementById("output");
    renderEditor(output, output.textContent, "javascript");
  };
  window.operationExplanation = function (path, operationId="") {
    if (!isEn()) return base.operationExplanation(path, operationId);
    if (endpointHelpEn[path]) return endpointHelpEn[path];
    if (path.startsWith("/account/passkeys") || path.startsWith("/auth/passkey")) return "WebAuthn/passkey ceremony. Preserve and return the challenge without modification.";
    if (path.startsWith("/admin/")) return "Tenant administration operation; requires an owner session, IAL2 and the appropriate role.";
    if (path.startsWith("/scim/v2/")) return "SCIM 2.0 provisioning and synchronization for enterprise users and groups.";
    return `OpenAPI operation ${window.humanOperation(operationId || path)}.`;
  };
  window.authenticationHint = path => isEn() ? authEn(path) : base.authenticationHint(path);

  function detailFor(operation) {
    selectedOperation = operation;
    document.querySelectorAll(".operation").forEach(node => node.classList.toggle("selected", node.dataset.key === `${operation.method}:${operation.path}`));
    const root = document.getElementById("operationDetail");
    root.innerHTML = `<div class="detail-accent"></div><div class="detail-body"><div class="detail-kicker"><span class="http-method ${operation.method}">${operation.method}</span><span class="tag">${escaped(operation.tag)}</span></div><code class="detail-path">${escaped(operation.path)}</code><h2>${escaped(window.humanOperation(operation.operation_id))}</h2><p>${escaped(window.operationExplanation(operation.path, operation.operation_id))}</p><div class="detail-section"><b>${icon("lock")} ${t("احراز هویت", "Authentication")}</b><p>${escaped(window.authenticationHint(operation.path))}</p></div><div class="detail-section"><b>${icon("fact_check")} ${t("پاسخ‌های قرارداد", "Contract responses")}</b><p>${escaped(operation.responses.join(" · ") || "—")}</p></div><div class="detail-actions"><button id="detailRun" class="button primary">${icon("play_arrow")} ${t("باز کردن در Explorer", "Open in Explorer")}</button><a class="button secondary" href="/openapi.yaml" target="_blank">${icon("description")} OpenAPI</a></div></div>`;
    document.getElementById("detailRun").onclick = () => { window.configureRequest(operation.method, operation.path); window.setPanel("explorer"); };
  }
  function prepareReferenceWorkspace() {
    const list = document.getElementById("referenceList");
    if (document.getElementById("referenceWorkspace")) return;
    const workspace = document.createElement("div"); workspace.id="referenceWorkspace"; workspace.className="reference-workspace";
    list.parentNode.insertBefore(workspace, list); workspace.appendChild(list);
    const detail=document.createElement("aside"); detail.id="operationDetail"; detail.className="operation-detail"; workspace.appendChild(detail);
  }
  window.renderReference = function () {
    prepareReferenceWorkspace();
    const query=document.getElementById("refSearch").value.trim().toLowerCase(), tag=document.getElementById("tagFilter").value;
    const filtered=catalog.filter(operation=>(!tag||operation.tag===tag)&&(!query||`${operation.method} ${operation.path} ${operation.operation_id} ${operation.description} ${window.operationExplanation(operation.path,operation.operation_id)}`.toLowerCase().includes(query)));
    document.getElementById("refCount").textContent=t(`${filtered.length} از ${catalog.length} operation`,`${filtered.length} of ${catalog.length} operations`);
    const list=document.getElementById("referenceList");
    list.replaceChildren(...filtered.map(operation=>{const article=document.createElement("article");article.className="operation";article.dataset.key=`${operation.method}:${operation.path}`;article.tabIndex=0;article.innerHTML=`<span class="http-method ${operation.method}">${operation.method}</span><code class="operation-path">${escaped(operation.path)}</code><div class="operation-copy"><b>${escaped(window.humanOperation(operation.operation_id))}</b><small>${escaped(window.operationExplanation(operation.path,operation.operation_id))}</small><div class="tag-row"><span class="tag">${escaped(operation.tag)}</span>${operation.description?`<span class="tag">OpenAPI</span>`:""}</div></div><span class="response-codes">${escaped(operation.responses.join(" · ")||"—")}</span>`;article.onclick=()=>detailFor(operation);article.onkeydown=event=>{if(event.key==="Enter")detailFor(operation)};return article;}));
    const wanted=filtered.find(item=>selectedOperation&&item.path===selectedOperation.path&&item.method===selectedOperation.method)||filtered[0];
    if(wanted) detailFor(wanted); else document.getElementById("operationDetail").innerHTML=`<div class="empty"><span class="ms">search</span><h3>${t("نتیجه‌ای نیست","No matching operation")}</h3></div>`;
  };

  const purpose = value => ({signup_email:t("تأیید ثبت‌نام","Signup verification"),password_reset:t("بازیابی رمز","Password recovery"),email_change:t("تغییر ایمیل","Email change"),phone_verification:t("تأیید موبایل","Phone verification")})[value]||value;
  window.messageCard = function(message){const card=document.createElement("article");card.className="card";const canVerify=["signup_email","email_change","phone_verification"].includes(message.purpose);card.innerHTML=`<div class="message-head"><span class="purpose">${escaped(purpose(message.purpose))}</span><span class="date">${new Date(message.received_at||Date.now()).toLocaleString(isEn()?"en-US":"fa-IR")}</span></div><div class="destination">${escaped(message.destination)}</div><div class="secret-grid"><div class="secret"><label>verification_id</label><code>${escaped(message.verification_id)}</code></div><div class="secret"><label>one-time secret</label><code>${escaped(message.secret)}</code></div></div><div class="actions"></div>`;const actions=card.querySelector(".actions");if(canVerify){const button=document.createElement("button");button.className=`button ${message.demo_verified?"verified":"primary"}`;button.innerHTML=message.demo_verified?`${icon("check_circle")} ${t("تأیید شده","Verified")}`:`${icon("verified_user")} ${t("تأیید همین حساب","Verify this account")}`;button.disabled=message.demo_verified;button.onclick=()=>window.verify(message.index,button);actions.append(button)}[[t("کپی ID","Copy ID"),message.verification_id],[t("کپی Secret","Copy secret"),message.secret]].forEach(([label,value])=>{const button=document.createElement("button");button.className="button secondary";button.innerHTML=`${icon("content_copy")} ${label}`;button.onclick=()=>window.copy(value);actions.append(button)});return card};

  function applyGuideCopy() {
    const copy=guideCopy[locale], guide=document.getElementById("guide");
    guide.querySelector(".guide-hero h2").textContent=copy.heroTitle; guide.querySelector(".guide-hero p").innerHTML=copy.heroBody;
    const titles=guide.querySelectorAll(".section-title"); titles[0].querySelector("h2").textContent=copy.pathTitle; titles[0].querySelector("p").textContent=copy.pathSub;
    guide.querySelectorAll(".choice").forEach((node,index)=>{node.querySelector(".number").textContent=isEn()?String(index+1):["۱","۲","۳","۴"][index];node.querySelector("h3").textContent=copy.choices[index][0];node.querySelector("p").textContent=copy.choices[index][1]});
    titles[1].querySelector("h2").textContent=copy.flowTitle;titles[1].querySelector("p").textContent=copy.flowSub;
    guide.querySelectorAll(".flow-step").forEach((node,index)=>{node.querySelector("b").textContent=copy.flows[index][0];node.querySelector("small").textContent=copy.flows[index][1]});
    titles[2].querySelector("h2").textContent=copy.conceptTitle;
    guide.querySelectorAll(".concept").forEach((node,index)=>{node.querySelector("h3").textContent=copy.concepts[index][0];node.querySelector("p").textContent=copy.concepts[index][1]});
  }
  function applyUtilityCopy() {
    const nav=Array.from(document.querySelectorAll(".nav em")); const names=isEn()?["Quickstart","API reference","API Explorer & examples","Verification inbox"]:["راهنمای شروع","مرجع کامل API","API Explorer و مثال‌ها","صندوق verification"];nav.forEach((node,index)=>node.textContent=names[index]);
    document.querySelector(".nav-label").textContent=isEn()?"WORKSPACE":"فضای توسعه";
    document.getElementById("localStatus").textContent=t("محیط لوکال فعال","Local environment online");document.querySelector(".local b").textContent=t("OpenProof محلی","Local OpenProof");document.getElementById("languageLabel").textContent=isEn()?"FA":"EN";
    const reference=document.getElementById("reference");reference.querySelector(".hint").innerHTML=t("این فهرست مستقیماً از <b>docs/openapi.yaml</b> ساخته می‌شود؛ بنابراین endpointهای Account، Auth، OAuth، Web3، Evidence، Admin و SCIM را یکجا می‌بینی.","This catalog is generated directly from <b>docs/openapi.yaml</b>, so Account, Auth, OAuth, Web3, Evidence, Admin and SCIM stay in one searchable contract.");
    document.getElementById("refSearch").placeholder=t("جستجو در path، operation یا توضیح…","Search path, operation or description…");document.querySelector("#tagFilter option").textContent=t("همه گروه‌ها","All groups");
    document.querySelector("#inbox .hint").innerHTML=t("بعد از ثبت‌نام، پیام واقعی delivery webhook اینجا ظاهر می‌شود. برای تست از ایمیل <b>example.test</b> و رمز غیرواقعی استفاده کن.","After signup, the real delivery-webhook message appears here. Use an <b>example.test</b> address and a disposable password for local testing.");
    document.getElementById("send").innerHTML=`${icon("send")} ${t("ارسال درخواست","Send request")}`;document.getElementById("copyCode").lastChild && (document.getElementById("copyCode").textContent=t("کپی مثال","Copy example"));
    document.getElementById("openReference").textContent=t("مرجع کامل API","Complete API reference");
    document.querySelector("#explorer a[href='/openapi.yaml']").textContent=t("OpenAPI خام","Raw OpenAPI contract");
    const requestInfo=document.querySelectorAll(".request-info .info-box b");if(requestInfo[1])requestInfo[1].textContent=t("مدل احراز این درخواست","Request authentication");
    document.querySelector(".response-head>span:not(.editor-chrome)")?.replaceChildren(document.createTextNode(t("پاسخ واقعی OpenProof","Live OpenProof response")));
    document.getElementById("authHeader").placeholder=t("Authorization اختیاری: Bearer ACCESS_TOKEN","Optional Authorization: Bearer ACCESS_TOKEN");
    const output=document.getElementById("output");if(!output.dataset.rawCode||output.dataset.rawCode.includes("برای دیدن خروجی"))renderEditor(output,t("برای دیدن خروجی، یکی از APIها را اجرا کنید.","Run an API operation to inspect its response."),"javascript");
    const presetNames=isEn()?["Service readiness","OIDC discovery","JWKS keys","User signup","Two-step login","Session profile","PKCE token","Service token","Start Web3 / SIWE"]:["آمادگی سرویس","OIDC Discovery","کلیدهای JWKS","ثبت‌نام کاربر","ورود دومرحله‌ای","پروفایل session","Token با PKCE","Token سرویس","شروع Web3 / SIWE"];
    document.querySelectorAll(".preset span:last-child").forEach((node,index)=>node.textContent=presetNames[index]);
  }
  function setLocale(next) {
    locale=next;localStorage.setItem("openproof.portal.locale",locale);document.documentElement.lang=locale;document.documentElement.dir=isEn()?"ltr":"rtl";
    applyGuideCopy();applyUtilityCopy();
    const active=document.querySelector(".nav.active")?.dataset.panel||"guide", meta=panelCopy[locale][active];document.getElementById("title").textContent=meta[0];document.getElementById("subtitle").textContent=meta[1];
    if(catalog?.length)window.renderReference();window.loadMessages();
    document.getElementById("requestDetails").textContent=window.operationExplanation(document.getElementById("path").value);document.getElementById("authHint").textContent=window.authenticationHint(document.getElementById("path").value);
    window.updateCode();
  }
  window.setPanel = function(name){base.setPanel(name);const meta=panelCopy[locale][name];document.getElementById("title").textContent=meta[0];document.getElementById("subtitle").textContent=meta[1]};
  window.toast = text => base.toast(isEn()&&text==="کپی شد"?"Copied":text);
  document.getElementById("languageToggle").onclick=()=>setLocale(isEn()?"fa":"en");
  prepareReferenceWorkspace();addChrome();
  const code=document.getElementById("codeOutput");renderEditor(code,code.textContent,activeLanguage||"curl");
  const output=document.getElementById("output");renderEditor(output,output.textContent,"javascript");
  const dynamicTranslations={"در حال ارسال…":"Sending…","ارسال درخواست":"Send request","در حال تأیید…":"Verifying…","تأیید همین حساب":"Verify this account","تأیید شده":"Verified","خطا":"Error"};
  new MutationObserver(records=>{if(!isEn())return;for(const record of records){const node=record.target.nodeType===Node.TEXT_NODE?record.target:record.target.firstChild;if(node?.nodeType===Node.TEXT_NODE){const value=node.textContent.trim();if(dynamicTranslations[value])node.textContent=node.textContent.replace(value,dynamicTranslations[value]);}}}).observe(document.body,{subtree:true,childList:true,characterData:true});
  setLocale(locale);
})();
