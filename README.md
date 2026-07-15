# cloudtse

Development-only **BSI TR-03153 compatible cloud TSE** for POS integration testing. Not certified — not for production fiscal signing.

## Quick start

**Build** (Debian/Ubuntu):

```bash
sudo apt install build-essential libsqlite3-dev libssl-dev   # once
make -C c
```

| Package | Why |
|---------|-----|
| `build-essential` | `gcc`, `make` |
| `libsqlite3-dev` | SQLite headers (`sqlite3.h`) |
| `libssl-dev` | OpenSSL headers (`openssl/sha.h`) and `libcrypto` |

On other distros, install the equivalent `-dev` packages for SQLite 3 and OpenSSL.

**Simulator** (no hardware — default when running the binary directly):

```bash
CLOUDTSE_TSE_MODE=sim ./c/cloudtse
# or
./start.sh sim
```

**Hardware** (Swissbit TSE via WormAPI — default for `start.sh`):

```bash
# Place the linux64 libWormAPI.so from the Swissbit SDK at libWormAPI/libWormAPI.so
sudo ./start.sh
```

`start.sh` sets `LD_LIBRARY_PATH`, picks up `libWormAPI/libWormAPI.so`, and tries to mount the TSE partition at `/mnt/tse`. If mount init fails, the C code falls back to block I/O on `CLOUDTSE_TSE_DEVICE` (default `/dev/sda`).

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

## TSE modes

| Mode | How to run | Signing |
|------|------------|---------|
| **sim** | `CLOUDTSE_TSE_MODE=sim` or `./start.sh sim` | Software simulator (fake serial, no TSE) |
| **hardware** | `./start.sh` or `CLOUDTSE_TSE_MODE=hardware` | Real Swissbit TSE via WormAPI |

In hardware mode, `/tssdetails` `serial` comes from the physical TSE when WormAPI loads successfully. If init fails, the server falls back to simulator signing and logs a warning.

Hardware mode needs the **linux64** `libWormAPI.so`. Download from the [Swissbit TSE connector](https://www.mytivi.at/tseconnector/swissbit/nativelibs/linux64/libWormAPI.so) or the SDK, and place it at `libWormAPI/libWormAPI.so`.

On a brand-new/factory-reset TSE (`initializationState == UNINITIALIZED`), the server automatically runs the one-time `worm_tse_setup` provisioning sequence (self-test → setup with the Swissbit credential seed → self-test again) using the admin PIN/PUK and time-admin PIN from config, generating and persisting them to the SQLite DB if not set. Watch the startup log for the generated credentials the first time this runs — set `CLOUDTSE_WORM_ADMIN_PIN` / `CLOUDTSE_WORM_ADMIN_PUK` / `CLOUDTSE_WORM_TIME_ADMIN_PIN` explicitly if you want to control them instead.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDTSE_PORT` | `20001` | Listen port |
| `CLOUDTSE_HOST` | `0.0.0.0` | Bind address |
| `CLOUDTSE_EAS_CODE` | `12345678` | Expected EAS code (`*` = accept any) |
| `CLOUDTSE_ALLOWED_CLIENT_SERIAL` | — (open) | Comma-separated `client_id` allowlist for `POST /oauth/token`. Empty/unset = any client with a valid EAS code may register |
| `CLOUDTSE_TSE_SERIAL` | 64-char hex | TSE serial in sim mode (`serial` / `serialNumber`) |
| `CLOUDTSE_TSE_MODE` | `sim` (`hardware` via `start.sh`) | `sim`, `hardware`, `hw`, or `1` |
| `CLOUDTSE_WORM_LIB` | `libWormAPI/libWormAPI.so` | Path to WormAPI shared library |
| `CLOUDTSE_WORM_PATH` | auto | Mount path with `TSE_INFO.DAT` (e.g. `/mnt/tse`) |
| `CLOUDTSE_TSE_DEVICE` | `/dev/sda` | Block device for direct TSE access |
| `CLOUDTSE_WORM_ADMIN_PIN` | auto-generated | TSE admin PIN (5 digits). Auto-generated and cached in the DB on first run against an uninitialized TSE if not set |
| `CLOUDTSE_WORM_ADMIN_PUK` | auto-generated | TSE admin PUK (6 digits). Same auto-provisioning behavior as the admin PIN |
| `CLOUDTSE_WORM_TIME_ADMIN_PIN` | auto-generated | TSE time-admin PIN (5 digits). Same auto-provisioning behavior as the admin PIN |
| `CLOUDTSE_WORM_CREDENTIAL_SEED` | `SwissbitSwissbit` | Credential seed used to provision a brand-new/uninitialized TSE via `worm_tse_setup`. Only override if your TSE reseller issued a different seed |
| `CLOUDTSE_PUBLIC_IP` | — | IP shown to clients when auto-detect fails |
| `CLOUDTSE_DB_PATH` | `data/cloudtse.db` | SQLite persistence |
| `CLOUDTSE_LOG` | `1` | Set `0` to disable request logging |
| `CLOUDTSE_LEAF_CERTIFICATE` | `SIMULATOR` | Base64-encoded leaf certificate or path to a PEM certificate file (used in simulator mode) |

State (clients, transactions, counters, OAuth tokens) is stored in SQLite.

### Custom Leaf Certificate in Simulator Mode

To test integration with client apps that display the TSE's leaf certificate, you can configure a self-signed ECDSA certificate. *Note: In simulator mode, this certificate is only used for display (e.g. at the `/tssdetails` endpoint) and is not used for signing transactions (transaction signatures in simulator mode remain mock/randomized values).*

1. Generate the ECDSA private key using the `prime256v1`/`secp256r1` curve:
   ```bash
   openssl ecparam -name prime256v1 -genkey -noout -out leaf-key.pem
   ```

2. Generate the self-signed certificate:
   ```bash
   openssl req -new -x509 -key leaf-key.pem -out leaf-cert.pem -days 3650 -subj "/CN=TSE-Simulator-Self-Signed"
   ```

3. Configure it in your `.env` file using the path to the file:
   ```env
   CLOUDTSE_LEAF_CERTIFICATE=/home/seb/src/cloudtse/leaf-cert.pem
   ```
   *(Alternatively, you can copy the raw base64 content directly into `CLOUDTSE_LEAF_CERTIFICATE` without linebreaks or PEM headers).*


## Project layout

```
start.sh            # launcher (hardware by default, `sim` subcommand)
libWormAPI/         # place libWormAPI.so here for hardware mode
c/                  # C implementation (API + SQLite DB)
  Makefile
  src/              # handlers, HTTP server, SQLite store, WormAPI integration
sources/            # decompiled reference client (not executed)
```

## License / disclaimer

Development only — not BSI-certified. Simulator mode is for integration testing without a TSE. Hardware mode talks to a real Swissbit TSE but this stack is still not certified for production fiscal signing.
