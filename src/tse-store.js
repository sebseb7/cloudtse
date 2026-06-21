import { randomBytes } from "node:crypto";
import { config } from "./config.js";
import { normalizeTseSerial } from "./tse-response.js";
import { db, getSetting, incrementCounter, setSetting } from "./db.js";

function nowIso() {
  return new Date().toISOString();
}

function makeSignature(counter) {
  return randomBytes(32).toString("base64");
}

const insertClient = db.prepare(`
  INSERT INTO clients (serial_number, registered_at, state, type_of_system, meta_json)
  VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(serial_number) DO UPDATE SET
    registered_at = excluded.registered_at,
    state = excluded.state,
    type_of_system = excluded.type_of_system,
    meta_json = excluded.meta_json
`);

const getClientStmt = db.prepare("SELECT * FROM clients WHERE serial_number = ?");

const insertTransaction = db.prepare(`
  INSERT INTO transactions (
    transaction_number, client_id, external_transaction_id,
    process_type, process_data, state, time_start,
    signature_counter, signature_value
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const getTransaction = db.prepare(`
  SELECT * FROM transactions WHERE transaction_number = ?
`);

const finishTransactionStmt = db.prepare(`
  UPDATE transactions SET
    process_type = ?,
    process_data = ?,
    state = ?,
    time_end = ?,
    signature_counter = ?,
    signature_value = ?
  WHERE transaction_number = ?
`);

const countClients = db.prepare("SELECT COUNT(*) AS n FROM clients");

function rowToClient(row) {
  return {
    serialNumber: row.serial_number,
    registeredAt: row.registered_at,
    state: row.state,
    typeOfSystem: row.type_of_system,
    ...(row.meta_json ? JSON.parse(row.meta_json) : {}),
  };
}

function rowToTransaction(row) {
  return {
    transactionNumber: row.transaction_number,
    clientId: row.client_id,
    externalTransactionId: row.external_transaction_id,
    processType: row.process_type,
    processData: row.process_data,
    state: row.state,
    timeStart: row.time_start,
    timeEnd: row.time_end,
    signatureCounter: row.signature_counter,
    signatureValue: row.signature_value,
    serialNumber: normalizeTseSerial(getSetting("tse_serial", config.tseSerial)),
  };
}

export class TseStore {
  constructor() {
    this.serialNumber = normalizeTseSerial(getSetting("tse_serial", config.tseSerial));
    this.initialized = true;
    this.createdAt = getSetting("created_at", nowIso());
  }

  registerClient(serialNumber, meta = {}) {
    const client = {
      serialNumber,
      registeredAt: nowIso(),
      state: "REGISTERED",
      ...meta,
    };

    insertClient.run(
      serialNumber,
      client.registeredAt,
      client.state,
      null,
      Object.keys(meta).length ? JSON.stringify(meta) : null,
    );

    return client;
  }

  getClient(serialNumber) {
    const row = getClientStmt.get(serialNumber);
    return row ? rowToClient(row) : null;
  }

  startTransaction(clientId, { processType = "", processData = "", externalTransactionId = null } = {}) {
    return db.transaction(() => {
      const transactionNumber = incrementCounter("transaction_counter");
      const signatureCounter = incrementCounter("signature_counter");
      const logTime = nowIso();
      const signatureValue = makeSignature(signatureCounter);

      insertTransaction.run(
        transactionNumber,
        clientId,
        externalTransactionId,
        processType,
        processData,
        "ACTIVE",
        logTime,
        signatureCounter,
        signatureValue,
      );

      return rowToTransaction(getTransaction.get(transactionNumber));
    })();
  }

  finishTransaction(clientId, transactionNumber, { processType = "", processData = "" } = {}) {
    return db.transaction(() => {
      const row = getTransaction.get(Number(transactionNumber));
      if (!row || row.state !== "ACTIVE") {
        const err = new Error("No open transaction for this number");
        err.code = "ErrorNoTransaction";
        throw err;
      }

      const signatureCounter = incrementCounter("signature_counter");
      const timeEnd = nowIso();
      const signatureValue = makeSignature(signatureCounter);

      finishTransactionStmt.run(
        processType || row.process_type,
        processData || row.process_data,
        "FINISHED",
        timeEnd,
        signatureCounter,
        signatureValue,
        Number(transactionNumber),
      );

      return rowToTransaction(getTransaction.get(Number(transactionNumber)));
    })();
  }

  info() {
    return {
      serialNumber: this.serialNumber,
      signatureCounter: Number(getSetting("signature_counter", "0")),
      transactionCounter: Number(getSetting("transaction_counter", "0")),
      registeredClients: countClients.get().n,
      initialized: this.initialized,
      createdAt: this.createdAt,
      fccVersion: config.fccVersion,
      dbPath: config.dbPath,
    };
  }

}

export const store = new TseStore();
