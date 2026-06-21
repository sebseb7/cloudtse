import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const env = process.env;
const rootDir = dirname(fileURLToPath(import.meta.url));

export const config = {
  host: env.CLOUDTSE_HOST ?? "0.0.0.0",
  port: Number(env.CLOUDTSE_PORT ?? 20001),

  /** Public IP shown to POS clients when the host only has a private interface address. */
  publicIp: env.CLOUDTSE_PUBLIC_IP?.trim() || null,

  /** EAS-Code from TSE setup — set to "*" to accept any code (dev only). */
  easCode: env.CLOUDTSE_EAS_CODE ?? "12345678",

  /** Fixed TSE serial (hex) returned after successful linking. */
  tseSerial: env.CLOUDTSE_TSE_SERIAL ?? "A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF",

  fccVersion: env.CLOUDTSE_FCC_VERSION ?? "4.4.0-sim",
  logRequests: env.CLOUDTSE_LOG !== "0",
  dbPath: env.CLOUDTSE_DB_PATH ?? join(rootDir, "..", "data", "cloudtse.db"),
};
