import { networkInterfaces } from "node:os";
import { config } from "../config.js";

const PUBLIC_IP_SOURCES = [
  "https://checkip.amazonaws.com",
  "https://api.ipify.org",
];

export function localIps() {
  const ips = [];
  for (const iface of Object.values(networkInterfaces())) {
    for (const addr of iface ?? []) {
      if (addr.family === "IPv4" && !addr.internal) {
        ips.push(addr.address);
      }
    }
  }
  return ips.length ? ips : ["127.0.0.1"];
}

async function fetchPublicIp() {
  for (const url of PUBLIC_IP_SOURCES) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (!res.ok) continue;
      const ip = (await res.text()).trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip;
    } catch {
      // try next source
    }
  }
  return null;
}

/** Public IP for POS clients (NAT/firewall); env override, else outbound lookup. */
export async function resolvePublicIp() {
  if (config.publicIp) return config.publicIp;
  return fetchPublicIp();
}
