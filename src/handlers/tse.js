import { randomBytes } from "node:crypto";
import { config } from "../config.js";
import { loadOAuthToken, saveOAuthToken } from "../db.js";
import { store } from "../tse-store.js";
import { parseBasicAuth, pick } from "../utils/http.js";
import {
  finishTransactionResponse,
  infoResponse,
  startTransactionResponse,
  tssDetailsResponse,
} from "../tse-response.js";

function issueToken(clientSerial) {
  const token = randomBytes(24).toString("hex");
  saveOAuthToken(token, clientSerial);
  return token;
}

export function parseBearerToken(headers = {}) {
  const auth = headers.authorization ?? headers.Authorization;
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice(7).trim();
}

export function validateBearer(headers = {}) {
  const token = parseBearerToken(headers);
  if (!token) return null;
  return loadOAuthToken(token);
}

export function requireBearer(headers = {}) {
  const session = validateBearer(headers);
  if (!session) return unauthorized("Invalid or missing Bearer token");
  return null;
}

/** OAuth: Authorization: Basic base64(Kassen-ID:EAS-Code) */
export function extractOAuthCredentials(headers = {}) {
  const basic = parseBasicAuth(headers);
  return {
    serial: basic?.clientId?.trim() ?? "",
    code: basic?.clientSecret ?? "",
  };
}

export function validateEasCode(headers = {}) {
  const { code } = extractOAuthCredentials(headers);
  if (config.easCode === "*") return true;
  return String(code) === String(config.easCode);
}

export function unauthorized(reason = "Invalid EAS code") {
  return {
    status: 401,
    body: {
      error: "unauthorized",
      error_description: reason,
      message: reason,
    },
  };
}

export function handleHealth() {
  const info = store.info();
  return {
    status: 200,
    body: {
      status: "ok",
      service: "cloudtse",
      version: config.fccVersion,
      ...info,
    },
  };
}

/** POST /oauth/token with Authorization: Basic base64(Kassen-ID:EAS-Code) */
export function handleOAuth(_body, _query, headers = {}) {
  const { serial, code } = extractOAuthCredentials(headers);

  if (!parseBasicAuth(headers)) {
    return unauthorized("Missing Authorization: Basic header");
  }
  if (!validateEasCode(headers)) {
    return unauthorized(`Invalid EAS code (got: ${code ? "[present]" : "[missing]"})`);
  }

  const clientSerial = serial || "unknown";
  if (clientSerial !== "unknown") {
    store.registerClient(clientSerial);
  }

  const accessToken = issueToken(clientSerial);

  return {
    status: 200,
    body: {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 86400,
      scope: "tse",
    },
  };
}

function resolveClientId(body, headers = {}) {
  const fromBody = pick(body, ["clientId"]);
  if (fromBody) return String(fromBody).trim();

  const session = validateBearer(headers);
  if (session?.clientSerial) return String(session.clientSerial).trim();

  return "default";
}

/** POST /transaction */
export function handleStartTransaction(body, headers = {}) {
  const authErr = requireBearer(headers);
  if (authErr) return authErr;

  const clientId = resolveClientId(body, headers);
  const processType = pick(body, ["processType"]) ?? "";
  const processData = pick(body, ["processData"]) ?? "";
  const externalTransactionId = pick(body, ["externalTransactionId"]);

  const tx = store.startTransaction(clientId, { processType, processData, externalTransactionId });

  return {
    status: 200,
    body: startTransactionResponse(tx),
  };
}

/** PUT /transaction/:id */
export function handleFinishTransaction(body, transactionNumber, headers = {}) {
  const authErr = requireBearer(headers);
  if (authErr) return authErr;

  const clientId = resolveClientId(body, headers);
  const processType = pick(body, ["processType"]) ?? "";
  const processData = pick(body, ["processData"]) ?? "";
  const txNum = transactionNumber;

  try {
    const tx = store.finishTransaction(clientId, txNum, { processType, processData });
    return {
      status: 200,
      body: finishTransactionResponse(tx),
    };
  } catch (err) {
    return {
      status: 400,
      body: { code: err.code ?? "transaction_error", message: err.message },
    };
  }
}

/** GET /tssdetails — client reads "serial" for TSE cache and TseInfo fields */
export function handleTssDetails(headers = {}) {
  const authErr = requireBearer(headers);
  if (authErr) return authErr;

  return {
    status: 200,
    body: tssDetailsResponse(store.info().serialNumber),
  };
}

/** GET /info — called after /tssdetails during link/setup */
export function handleInfo(headers = {}) {
  const authErr = requireBearer(headers);
  if (authErr) return authErr;

  const info = store.info();
  return {
    status: 200,
    body: infoResponse({
      registeredClients: info.registeredClients,
      transactionCounter: info.transactionCounter,
    }),
  };
}
