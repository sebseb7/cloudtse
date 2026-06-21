/** Decode TSE processData (typically base64 UTF-8 receipt payload). */
export function decodeProcessData(raw) {
  if (raw == null || raw === "") {
    return null;
  }
  try {
    const decoded = Buffer.from(String(raw), "base64").toString("utf8");
    if (!decoded || /^[\x00-\x08\x0e-\x1f\x7f-\xff]*$/.test(decoded)) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

export function isTransactionPath(path) {
  const p = (path ?? "").replace(/\/+$/, "") || "/";
  return p === "/transaction" || /^\/transaction\/\d+$/.test(p);
}

export function logTransactionPayload(label, body = {}) {
  const fields = [
    ["clientId", body.clientId],
    ["processType", body.processType],
    ["externalTransactionId", body.externalTransactionId],
    ["processData", body.processData],
  ];

  console.log(`  ${label}:`);
  for (const [key, value] of fields) {
    if (value != null && value !== "") {
      console.log(`    ${key}:`, value);
    }
  }

  const decoded = decodeProcessData(body.processData);
  if (decoded != null) {
    console.log("    processData (decoded):", decoded);
  } else if (body.processData) {
    console.log("    processData (decoded): [not base64 UTF-8]");
  }
}
