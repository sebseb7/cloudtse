# cloudtse

Development-only **BSI TR-03153 compatible cloud TSE** for POS integration testing. Not certified — not for production fiscal signing.

## Quick start

### C (recommended — ~76 KB RSS vs ~50+ MB for Node)

```bash
sudo apt install libsqlite3-dev   # once
make -C c
./c/cloudtse
```

### Node.js

```bash
npm install
npm start
```

Listens on `0.0.0.0:20001` by default. All requests are logged to stdout.

## POS client setup

**TSE → Cloud TSE → Link** (menu labels vary by POS vendor)

| Field | Value |
|-------|--------|
| IP | Address printed at startup (`Client IP`) |
| Port | `20001` |
| Seriennummer | Your Kassen-ID / EAS serial (saved locally as EAS Sn) |
| EAS-Code | `12345678` (default) |

After code changes, restart the server and **re-link** the TSE so `/tssdetails` is fetched again.

## API

| Method | Path | Notes |
|--------|------|--------|
| `POST` | `/oauth/token` | Basic auth `Kassen-ID:EAS-Code`, form body `grant_type=client_credentials` |
| `GET` | `/tssdetails` | Returns **`serial`** (TSE hex) — required for link and receipt footer |
| `GET` | `/info` | `maxNumberClients`, `maxNumberTransactions`, `currentNumberOfTransactions` |
| `POST` | `/transaction` | Start sale |
| `PUT` | `/transaction/:id` | Finish sale |
| `GET` | `/health` | Dev status |

Receipt **TSE** line uses `/tssdetails` field `serial` (cached by the client). **POS** line uses the locally stored Kassen-ID, not the finish response.

Response shapes are aligned with the reference client in `sources/`.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDTSE_PORT` | `20001` | Listen port |
| `CLOUDTSE_HOST` | `0.0.0.0` | Bind address |
| `CLOUDTSE_EAS_CODE` | `12345678` | Expected EAS code (`*` = accept any) |
| `CLOUDTSE_TSE_SERIAL` | 64-char hex | TSE serial returned as `serial` / `serialNumber` |
| `CLOUDTSE_PUBLIC_IP` | — | IP shown to clients when auto-detect fails |
| `CLOUDTSE_DB_PATH` | `data/cloudtse.db` | SQLite persistence |
| `CLOUDTSE_LOG` | `1` | Set `0` to disable request logging |

State (clients, transactions, counters, OAuth tokens) is stored in SQLite.

## Project layout

```
c/                  # C implementation (same API + SQLite DB)
  Makefile
  src/              # handlers, HTTP server, SQLite store
src/                # Node.js implementation
  index.js          # entrypoint
  server.js         # routing
  handlers/tse.js   # OAuth + transaction handlers
  tse-response.js   # TR-03153 response builders
  tse-store.js      # business logic
  db.js             # SQLite
sources/            # decompiled reference client (not executed)
```

## License / disclaimer

Simulator only. Do not use for production fiscal signing.
