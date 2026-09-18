import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const portalHtml = fs.readFileSync(
  path.join(moduleDirectory, "local-demo-portal.html"), "utf8",
);
const iconFont = fs.readFileSync(
  path.join(moduleDirectory, "assets/material-symbols-rounded-subset.ttf"),
);
const portalStyles = fs.readFileSync(
  path.join(moduleDirectory, "local-demo-portal-v3.css"), "utf8",
);
const portalEnhancements = fs.readFileSync(
  path.join(moduleDirectory, "local-demo-portal-v3.js"), "utf8",
);

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(server.address().port);
    });
  });
}

function readBody(request, maximumBytes = 1_048_576) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > maximumBytes) {
        reject(new Error("request body is too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function sendJson(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function publicHeaders(headers) {
  const safe = {};
  for (const name of ["content-type", "content-length", "location", "x-request-id"]) {
    if (headers[name] !== undefined) safe[name] = headers[name];
  }
  return safe;
}

export function parseOpenApiCatalog(source) {
  const operations = [];
  const lines = source.split(/\r?\n/);
  let inPaths = false;
  let currentPath = "";
  let pathParameters = [];
  let current;
  let collectingDescription = false;
  let descriptionIndent = 0;

  function finish() {
    if (!current) return;
    current.description = current.description.trim().replaceAll(/\s+/g, " ");
    operations.push(current);
    current = undefined;
  }

  function parseParameter(line) {
    const match = line.match(/^\s+- \{name:\s*([^,]+),\s*in:\s*(path|query|header),\s*required:\s*(true|false)/);
    if (!match) return undefined;
    const typeMatch = line.match(/type:\s*([^,}\]]+)/);
    const enumMatch = line.match(/enum:\s*\[([^,\]]+)/);
    const descriptionValue = line.match(/description:\s*([^,}]+)/);
    return {
      name: match[1].trim(),
      in: match[2],
      required: match[3] === "true",
      type: typeMatch?.[1]?.trim() ?? "string",
      example: enumMatch?.[1]?.trim() ?? "",
      description: descriptionValue?.[1]?.trim() ?? "",
    };
  }

  for (const line of lines) {
    if (line === "paths:") {
      inPaths = true;
      continue;
    }
    if (inPaths && /^components:/.test(line)) {
      finish();
      break;
    }
    if (!inPaths) continue;
    const pathMatch = line.match(/^  (\/[^:]+):\s*$/);
    if (pathMatch) {
      finish();
      currentPath = pathMatch[1];
      pathParameters = [];
      collectingDescription = false;
      continue;
    }
    const methodMatch = line.match(/^    (get|head|post|put|patch|delete):\s*$/i);
    if (methodMatch) {
      finish();
      current = {
        path: currentPath,
        method: methodMatch[1].toUpperCase(),
        operation_id: "",
        tag: "Other",
        description: "",
        responses: [],
        parameters: pathParameters.map((parameter) => ({ ...parameter })),
        has_request_body: false,
      };
      collectingDescription = false;
      continue;
    }
    if (!current) {
      const pathParameter = parseParameter(line);
      if (pathParameter) pathParameters.push(pathParameter);
      continue;
    }
    if (/^      requestBody:/.test(line)) current.has_request_body = true;
    const operationMatch = line.match(/^      operationId:\s*(.+)\s*$/);
    if (operationMatch) current.operation_id = operationMatch[1];
    const tagMatch = line.match(/^      tags:\s*\[([^\]]+)\]/);
    if (tagMatch) current.tag = tagMatch[1].split(",")[0].trim();
    const descriptionMatch = line.match(/^      description:\s*(.*)$/);
    if (descriptionMatch) {
      const value = descriptionMatch[1].trim();
      collectingDescription = value === ">-" || value === "|";
      descriptionIndent = 8;
      if (!collectingDescription) current.description += `${value} `;
      continue;
    }
    if (collectingDescription) {
      const indent = line.match(/^\s*/)[0].length;
      if (line.trim() && indent >= descriptionIndent) {
        current.description += `${line.trim()} `;
        continue;
      }
      collectingDescription = false;
    }
    const responseMatch = line.match(/^        ["']?(\d{3})["']?:/);
    if (responseMatch && !current.responses.includes(responseMatch[1])) {
      current.responses.push(responseMatch[1]);
    }
    const parameter = parseParameter(line);
    if (parameter) current.parameters.push(parameter);
  }
  return operations.filter((operation) => operation.path && operation.operation_id);
}

class CookieJar {
  #values = new Map();

  apply(setCookies) {
    for (const header of setCookies ?? []) {
      const [pair, ...attributes] = header.split(";");
      const separator = pair.indexOf("=");
      if (separator <= 0) continue;
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      const expired = attributes.some(
        (item) => item.trim().toLowerCase() === "max-age=0",
      );
      if (expired || value === "") this.#values.delete(name);
      else this.#values.set(name, value);
    }
  }

  header() {
    return [...this.#values].map(([name, value]) => `${name}=${value}`).join("; ");
  }

  clear() {
    this.#values.clear();
  }
}

function validApiPath(value) {
  return typeof value === "string"
    && /^\/[A-Za-z0-9._~!$&'()*+,;=:@/?%-]*$/.test(value)
    && !value.startsWith("//")
    && !value.includes("..")
    && !value.includes("#");
}

export async function startLocalDemoPortal(options) {
  const {
    notifications,
    requestOpenProof,
    targetBaseUrl,
    openApiPath,
    demoAccount,
  } = options;
  const jar = new CookieJar();
  const openApi = fs.readFileSync(openApiPath, "utf8");
  const catalog = parseOpenApiCatalog(openApi);

  async function proxy(
    method,
    requestPath,
    requestBody,
    requestedHeaders = {},
    credentialMode = "portal",
  ) {
    const normalizedMethod = String(method ?? "GET").toUpperCase();
    if (!["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"].includes(normalizedMethod)) {
      throw new Error("unsupported HTTP method");
    }
    if (!validApiPath(requestPath)) throw new Error("path must be a local OpenProof API path");

    let body = "";
    if (requestBody !== undefined && requestBody !== null && requestBody !== "") {
      body = typeof requestBody === "string" ? requestBody : JSON.stringify(requestBody);
    }
    const headers = {};
    for (const name of ["accept", "content-type", "authorization"]) {
      const value = requestedHeaders?.[name];
      if (typeof value === "string" && value.length <= 4096) headers[name] = value;
    }
    if (body && !headers["content-type"]) headers["content-type"] = "application/json";

    const started = performance.now();
    if (!["portal", "bearer", "none"].includes(credentialMode)) {
      throw new Error("credential mode must be portal, bearer or none");
    }
    const result = await requestOpenProof(requestPath, {
      method: normalizedMethod,
      body,
      headers,
      jar: credentialMode === "portal" ? jar : undefined,
    });
    return {
      status: result.status,
      duration_ms: Math.round((performance.now() - started) * 10) / 10,
      headers: publicHeaders(result.headers),
      body: result.body,
    };
  }

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    try {
      if (request.method === "GET" && url.pathname === "/") {
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "content-security-policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'",
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
        });
        const safeDemoAccount = JSON.stringify(demoAccount).replaceAll("<", "\\u003c");
        response.end(portalHtml
          .replaceAll("{{OPENPROOF_BASE_URL}}", targetBaseUrl)
          .replace("{{DEMO_ACCOUNT}}", safeDemoAccount));
        return;
      }
      if (request.method === "GET" && url.pathname === "/assets/material-symbols-rounded-subset.ttf") {
        response.writeHead(200, {
          "content-type": "font/ttf",
          "content-length": iconFont.length,
          "cache-control": "public, max-age=31536000, immutable",
          "x-content-type-options": "nosniff",
        });
        response.end(iconFont);
        return;
      }
      if (request.method === "GET" && url.pathname === "/assets/portal.css") {
        response.writeHead(200, {
          "content-type": "text/css; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        response.end(portalStyles);
        return;
      }
      if (request.method === "GET" && url.pathname === "/assets/portal.js") {
        response.writeHead(200, {
          "content-type": "text/javascript; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        response.end(portalEnhancements);
        return;
      }
      if (request.method === "GET" && url.pathname === "/openapi.yaml") {
        response.writeHead(200, {
          "content-type": "application/yaml; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        response.end(openApi);
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/context") {
        sendJson(response, 200, { target_base_url: targetBaseUrl });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/catalog") {
        sendJson(response, 200, { operations: catalog });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/session/status") {
        const result = await proxy("GET", "/account/profile", "", {}, "portal");
        sendJson(response, 200, {
          authenticated: result.status === 200,
          status: result.status,
          profile: result.status === 200 ? JSON.parse(result.body || "{}") : null,
        });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/messages") {
        sendJson(response, 200, {
          messages: notifications.map((message, index) => ({ index, ...message })).reverse(),
        });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/session/reset") {
        jar.clear();
        sendJson(response, 200, { cleared: true });
        return;
      }
      const verificationMatch = url.pathname.match(/^\/api\/messages\/(\d+)\/verify$/);
      if (request.method === "POST" && verificationMatch) {
        const message = notifications[Number.parseInt(verificationMatch[1], 10)];
        if (!message) {
          sendJson(response, 404, { error: "delivery message was not found" });
          return;
        }
        const verificationPaths = {
          signup_email: "/account/email/verify",
          email_change: "/account/email/change/verify",
          phone_verification: "/account/phone/verify",
        };
        const targetPath = verificationPaths[message.purpose];
        if (!targetPath) {
          sendJson(response, 409, {
            error: "this delivery purpose needs a different completion form",
          });
          return;
        }
        const result = await proxy("POST", targetPath, {
          verification_id: message.verification_id,
          secret: message.secret,
        });
        message.demo_verified = result.status >= 200 && result.status < 300;
        sendJson(response, 200, result);
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/request") {
        const raw = await readBody(request);
        const input = JSON.parse(raw || "{}");
        const result = await proxy(
          input.method,
          input.path,
          input.body,
          input.headers,
          input.credential_mode ?? "portal",
        );
        sendJson(response, 200, result);
        return;
      }
      sendJson(response, 404, { error: "not found" });
    } catch (error) {
      sendJson(response, 400, { error: error.message });
    }
  });

  const port = await listen(server);
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
