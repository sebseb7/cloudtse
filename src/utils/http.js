export function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export function parseBody(raw, contentType = "") {
  if (!raw) return {};

  const ct = contentType.toLowerCase();

  if (ct.includes("application/json")) {
    try {
      return JSON.parse(raw);
    } catch {
      return { _raw: raw };
    }
  }

  if (ct.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(raw));
  }

  try {
    return JSON.parse(raw);
  } catch {
    return { _raw: raw };
  }
}

export function sendJson(res, status, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    ...extraHeaders,
  });
  res.end(body);
}

export function sendText(res, status, text, contentType = "text/plain; charset=utf-8") {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": Buffer.byteLength(text),
    "Access-Control-Allow-Origin": "*",
  });
  res.end(text);
}

export function normalizePath(url) {
  const path = (url ?? "/").split("?")[0];
  return path.replace(/\/+$/, "") || "/";
}

export function pathMatch(path, pattern) {
  if (pattern === path) return true;
  if (pattern.endsWith("*") && path.startsWith(pattern.slice(0, -1))) return true;
  return false;
}

export function pick(obj, keys) {
  for (const key of keys) {
    if (obj?.[key] != null && obj[key] !== "") return obj[key];
  }
  return undefined;
}

/** Parse `Authorization: Basic <base64(client_id:client_secret)>`. */
export function parseBasicAuth(headers = {}) {
  const auth = headers.authorization ?? headers.Authorization;
  if (!auth?.startsWith("Basic ")) return null;

  try {
    const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
    const sep = decoded.indexOf(":");
    if (sep < 0) return { clientId: decoded, clientSecret: "" };
    return {
      clientId: decoded.slice(0, sep),
      clientSecret: decoded.slice(sep + 1),
    };
  } catch {
    return null;
  }
}
