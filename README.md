# ruckus-mcp

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)

MCP server for Ruckus Unleashed (tested on R500/R600, built-in Embedthis-Appweb web server). Uses [`aioruckus`](https://github.com/gabe565/aioruckus) to talk to the controller's AJAX API.

## Tools

**Monitoring**

| Tool | Description |
|---|---|
| `get_system_info` | Firmware version, AP count, operating mode, master AP |
| `get_aps` / `get_ap_stats` / `get_ap_groups` | Access points, their stats, and groups |
| `get_mesh_info` | Mesh topology: root/member APs, backhaul RSSI |
| `get_active_clients` | Connected clients (filter by SSID/AP) |
| `get_wlans` / `get_wlan_groups` / `get_vap_stats` | SSIDs, WLAN groups, VAP stats |
| `get_alarms` / `get_all_events` / `get_ap_events` / `get_wlan_events` / `get_syslog` | Events and logs |
| `get_rogues` | Rogue access points detected over the air |
| `get_blocked_clients` / `get_dpsks` / `get_acls` | Blocklist, DPSK keys, ACLs |
| `debug_api_methods` | List of all `aioruckus` methods — a diagnostic tool for development |

**Management**

| Tool | Description |
|---|---|
| `reboot_ap` / `show_ap_leds` / `hide_ap_leds` | Manage an access point by MAC |
| `enable_wlan` / `disable_wlan` / `set_wlan_password` | Manage an SSID |
| `block_client` / `unblock_client` | Manage a client by MAC |

## Setup

```bash
git clone <this-repo> ruckus-mcp && cd ruckus-mcp
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # fill in RUCKUS_HOST/USER/PASS, MCP_SECRET
uvicorn server:app --host 0.0.0.0 --port 8003
```

Systemd unit example: [`deploy/ruckus-mcp.service`](deploy/ruckus-mcp.service).

**Docker:**

```bash
docker build -t ruckus-mcp .
docker run -p 8003:8003 --env-file .env ruckus-mcp
```

## Security model

- Auth is an `Authorization: Bearer $MCP_SECRET` header on `/mcp`. **Unlike the other servers in this line-up**, the `Authorization` header is always required here — even without `MCP_SECRET` set, you still need to send `Authorization: Bearer ` (empty value). It's recommended to always set `MCP_SECRET`.
- `/.well-known/oauth-authorization-server` + `/oauth/authorize` + `/oauth/token` are a compatible stub for claude.ai custom connectors, which [don't support a static API key](https://claude.com/docs/connectors/building/authentication) — only full OAuth 2.1 or no auth at all. The actual protection is the Bearer token on `/mcp`.
- `redirect_uri` in `/oauth/authorize` is checked against an allowlist (`claude.ai`, `anthropic.com`, `console.anthropic.com`, `localhost`).
- **Important if you extend `get_system_info`**: `aioruckus.get_system_info(SystemStat.ALL)` returns the controller's **entire raw config**, including the local admin password in plaintext, TR-069/CWMP passwords, and cloud keys (AWS SNS, PubNub). `_clean_system_info()` in the code whitelists only the safe fields — if you add new fields to this tool's output, whitelist them explicitly, don't widen it via `**info` or similar.
- TLS verification to the controller is disabled (`ssl.CERT_NONE`, `SECLEVEL=0`) — typical Unleashed firmware uses self-signed certificates with a weak key. This is an intentional tradeoff for a trusted local network; don't point `RUCKUS_HOST` at anything outside your LAN/VPN.
- **Outbound transport**: the server itself does not terminate TLS — it listens on plain HTTP. If it's reachable beyond localhost/a trusted LAN (and especially if you're connecting it as a custom connector in claude.ai, where HTTPS is required), put TLS termination in front of it: Cloudflare Tunnel, Tailscale Funnel, nginx/Caddy + Let's Encrypt, etc. Without that, the Bearer token (`MCP_SECRET`) in the `Authorization` header goes out in plaintext. (This is a separate concern from the TLS verification *to* the controller described above.)

## Requirements

- Ruckus Unleashed (web UI on 443/8443).
- Python 3.11+.

## License

MIT — see [LICENSE](LICENSE).
