import { config } from "./config.js";
import {
  handleFinishTransaction,
  handleHealth,
  handleInfo,
  handleOAuth,
  handleStartTransaction,
  handleTssDetails,
} from "./handlers/tse.js";
import {
  normalizePath,
  parseBody,
  readBody,
  sendJson,
} from "./utils/http.js";

import {
  isTransactionPath,
  logTransactionPayload,
} from "./utils/tse-log.js";

function logRequest(req, path, body, headers = {}) {
  if (!config.logRequests) return;
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${path}`);
  if (headers.authorization) {
    console.log("  authorization:", headers.authorization);
  }
  if (Object.keys(body).length > 0) {
    if (isTransactionPath(path)) {
      logTransactionPayload("transaction payload", body);
    } else {
      console.log("  body:", JSON.stringify(body));
    }
  }
}

function logResponse(status, body) {
  if (!config.logRequests) return;
  console.log(`  → ${status}`);
  if (body != null) {
    console.log(JSON.stringify(body, null, 2));
  }
}

function routeGet(path, headers) {
  const p = normalizePath(path);

  if (p === "/tssdetails") {
    return handleTssDetails(headers);
  }

  if (p === "/info") {
    return handleInfo(headers);
  }

  if (p === "/" || p === "/health") {
    return handleHealth();
  }

  return {
    status: 404,
    body: { error: "not_found", message: `No handler for GET ${p}` },
  };
}

function routeWrite(method, path, body, _query, headers) {
  const m = method.toUpperCase();
  const p = normalizePath(path);

  if (m === "POST" && p === "/oauth/token") {
    return handleOAuth(body, _query, headers);
  }

  if (m === "POST" && p === "/transaction") {
    return handleStartTransaction(body, headers);
  }

  const txFinishMatch = p.match(/^\/transaction\/(\d+)$/);
  if ((m === "PUT" || m === "PATCH") && txFinishMatch) {
    return handleFinishTransaction(body, txFinishMatch[1], headers);
  }

  return {
    status: 404,
    body: { error: "not_found", message: `No handler for ${m} ${p}` },
  };
}

export async function handleRequest(req, res) {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const path = url.pathname;
  const query = Object.fromEntries(url.searchParams);

  let body = {};
  if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "OPTIONS") {
    const raw = await readBody(req);
    body = parseBody(raw, req.headers["content-type"] ?? "");
  }

  logRequest(req, path, body, req.headers);

  const method = req.method?.toUpperCase() ?? "GET";
  let result;

  if (method === "OPTIONS") {
    result = { status: 204, body: null, noBody: true };
  } else if (method === "GET" || method === "HEAD") {
    result = routeGet(path, req.headers);
  } else {
    result = routeWrite(method, path, body, query, req.headers);
  }

  logResponse(result.status, result.body ?? null);

  if (result.noBody) {
    res.writeHead(result.status, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    });
    res.end();
    return;
  }

  sendJson(res, result.status, result.body);
}

export function createServer() {
  return { handleRequest };
}
