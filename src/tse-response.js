import { config } from "./config.js";

/** BSI TSE serial = hex hash of signing public key (typically 32 bytes → 64 hex chars). */
export const DEFAULT_TSE_SERIAL =
  "A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF";

const HEX_SERIAL = /^[0-9A-Fa-f]+$/;

export function normalizeTseSerial(value) {
  const serial = String(value ?? "").trim();
  if (serial.length >= 32 && HEX_SERIAL.test(serial)) {
    return serial.toUpperCase();
  }
  return DEFAULT_TSE_SERIAL;
}

/**
 * Reference client parses logTime with SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").
 */
export function fccLogTime(isoString) {
  const d = new Date(isoString);
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}` +
    `T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
  );
}

/**
 * POST /transaction — transactionNumber, signatureCounter, signatureValue, logTime, serialNumber
 */
export function startTransactionResponse(tx) {
  return {
    transactionNumber: String(tx.transactionNumber),
    signatureCounter: String(tx.signatureCounter),
    signatureValue: tx.signatureValue,
    logTime: fccLogTime(tx.timeStart),
    serialNumber: normalizeTseSerial(tx.serialNumber),
  };
}

/**
 * PUT /transaction/:id — signatureCounter, signatureValue, logTime
 * (TSE serial on the receipt comes from cached GET /tssdetails "serial", not this response.)
 */
export function finishTransactionResponse(tx) {
  return {
    signatureCounter: String(tx.signatureCounter),
    signatureValue: tx.signatureValue,
    logTime: fccLogTime(tx.timeEnd ?? tx.timeStart),
  };
}

/**
 * GET /tssdetails — "serial" (TSE cache + receipt), plus timeFormat, encoding,
 * publicKey, algorithm, leafCertificate for TseInfo display
 */
export function tssDetailsResponse(serialNumber = config.tseSerial) {
  const serial = normalizeTseSerial(serialNumber);
  return {
    serial,
    timeFormat: "yyyy-MM-dd'T'HH:mm:ssX",
    encoding: "UTF-8",
    publicKey: serial,
    algorithm: "ecdsa-plain-SHA256",
    leafCertificate: "SIMULATOR",
  };
}

/**
 * GET /info — maxNumberClients, maxNumberTransactions, currentNumberOfTransactions
 */
export function infoResponse(counters = {}) {
  const {
    registeredClients = 0,
    transactionCounter = 0,
    maxClients = 100,
    maxTransactions = 500,
  } = counters;

  return {
    maxNumberClients: String(maxClients),
    maxNumberTransactions: String(maxTransactions),
    currentNumberOfTransactions: String(transactionCounter),
    registeredClients: String(registeredClients),
  };
}
