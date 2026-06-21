import { createServer as createHttpServer } from "node:http";
import { config } from "./config.js";
import { handleRequest } from "./server.js";
import { localIps, resolvePublicIp } from "./utils/network.js";

const httpServer = createHttpServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    console.error("Request error:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "internal_error", message: err.message }));
  });
});

httpServer.listen(config.port, config.host, async () => {
  const publicIp = await resolvePublicIp();
  const privateIps = localIps();

  console.log("");
  console.log("  BSI TR-03153 cloud TSE — development only");
  console.log("  ─────────────────────────────────────────────────────");
  console.log(`  Listening:  http://${config.host}:${config.port}`);
  if (publicIp) {
    console.log(`  Client IP:  ${publicIp}`);
  } else {
    for (const ip of privateIps) {
      console.log(`  Client IP:  ${ip}  (private — set CLOUDTSE_PUBLIC_IP or allow outbound HTTPS)`);
    }
  }
  console.log(`  Port:       ${config.port}`);
  console.log(`  EAS-Code:   ${config.easCode}`);
  console.log(`  TSE serial: ${config.tseSerial}`);
  console.log(`  Database:   ${config.dbPath}`);
  console.log("");
  console.log("    IP           = one of the addresses above");
  console.log("    Port         = 20001");
  console.log("    Seriennummer = your Kassen-ID / EAS serial");
  console.log(`    EAS-Code     = ${config.easCode}`);
  console.log("");
});

process.on("SIGINT", () => {
  httpServer.close(() => process.exit(0));
});
