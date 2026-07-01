import os
import json
import asyncio
import re
import logging
import aiohttp
import ssl
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse
from aioruckus import SystemStat
from aioruckus.ajaxsession import AjaxSession as _AjaxSession
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ruckus-mcp")

RUCKUS_HOST  = os.getenv("RUCKUS_HOST", "192.168.1.253")
RUCKUS_USER  = os.getenv("RUCKUS_USER", "admin")
RUCKUS_PASS  = os.getenv("RUCKUS_PASS", "")
MCP_SECRET   = os.getenv("MCP_SECRET", "")
DOMAIN       = os.getenv("DOMAIN", "ruckus-mcp.example.com")

if not RUCKUS_HOST: raise RuntimeError("RUCKUS_HOST not configured")
if not RUCKUS_USER: raise RuntimeError("RUCKUS_USER not configured")
if not RUCKUS_PASS: logger.warning("RUCKUS_PASS is empty")

STATIC_TOKEN = os.getenv("MCP_SECRET", "")
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")

app = FastAPI()


# ── Session ───────────────────────────────────────────────────────────────────

async def _make_session():
    """Ruckus R500/R600 (Embedthis-Appweb 3.4.2) не поддерживает HEAD через aiohttp.
    Патчим session.head = session.get. SECLEVEL=0 для слабого ключа сертификата
    (типично для самоподписанных сертификатов на старых прошивках Unleashed)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    websession = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=10),
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        connector=aiohttp.TCPConnector(keepalive_timeout=5, ssl=ctx),
    )
    websession.head = websession.get
    return websession


# ── Startup self-test ─────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    logger.info("Ruckus MCP starting → %s", RUCKUS_HOST)
    try:
        websession = await _make_session()
        async with _AjaxSession(websession, RUCKUS_HOST, RUCKUS_USER, RUCKUS_PASS,
                                 auto_cleanup_websession=True) as session:
            info = await session.api.get_system_info()
            logger.info("Ruckus login OK: %s", list(info.keys()) if isinstance(info, dict) else "ok")
    except Exception as e:
        logger.error("Ruckus login FAILED: %s", e)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _obj_to_dict(obj):
    if isinstance(obj, dict):
        return obj.copy()
    if hasattr(obj, "__dict__"):
        return dict(vars(obj))
    if hasattr(obj, "__slots__"):
        return {s: getattr(obj, s) for s in obj.__slots__ if hasattr(obj, s)}
    return {}

def _normalize_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":").replace(".", ":")
    plain = mac.replace(":", "")
    if len(plain) == 12 and ":" not in mac:
        mac = ":".join(plain[i:i+2] for i in range(0, 12, 2))
    if not MAC_RE.fullmatch(mac):
        raise ValueError(f"Invalid MAC: '{mac}'. Expected aa:bb:cc:dd:ee:ff")
    return mac

def _require(args, key):
    if key not in args or args[key] is None:
        raise ValueError(f"'{key}' is required")
    return args[key]

def _clean_ap(ap):
    ap = _obj_to_dict(ap)
    return {
        "name":       ap.get("name"),
        "mac":        ap.get("mac"),
        "ip":         ap.get("ip"),
        "model":      ap.get("model"),
        "serial":     ap.get("serial"),
        "status":     ap.get("status"),
        "uptime":     ap.get("uptime"),
        "clients":    ap.get("clients"),
        "channel-24": ap.get("channel-24") or ap.get("channel24") or ap.get("channel24g"),
        "channel-5":  ap.get("channel-5")  or ap.get("channel5")  or ap.get("channel5g"),
        "tx-power":   ap.get("tx-power")   or ap.get("txpower"),
        "firmware":   ap.get("firmware"),
        "description":ap.get("description"),
    }

def _clean_client(c):
    c = _obj_to_dict(c)
    keys = ["hostname","mac","ip","ssid","ap","ap-mac","radio-type","rssi","vlan","rx-bytes","tx-bytes","uptime"]
    return {k: c[k] for k in keys if k in c}

def _clean_alarm(a):
    a = _obj_to_dict(a)
    keys = ["id","severity","type","description","timestamp","cleared"]
    return {k: a[k] for k in keys if k in a}

def _clean_rogue(r):
    r = _obj_to_dict(r)
    keys = ["ssid","mac","channel","rssi","type","encryption","last-seen"]
    return {k: r[k] for k in keys if k in r}

def _clean_event(e):
    e = _obj_to_dict(e)
    keys = ["id","type","severity","description","timestamp","ap","client","ssid"]
    return {k: e[k] for k in keys if k in e}

def _clean_system_info(info):
    """get_system_info(SystemStat.ALL) отдаёт ПОЛНЫЙ сырой конфиг контроллера,
    включая admin.password в открытом виде, TR-069/CWMP пароли, AWS SNS и
    PubNub секретные ключи и т.п. Инструмент обещает только сводку по сети —
    поэтому здесь, как и в остальных _clean_* хелперах, вайтлистим только
    безопасные поля."""
    info     = _obj_to_dict(info)
    sysinfo  = info.get("sysinfo", {}) or {}
    identity = info.get("identity", {}) or {}
    cpu      = info.get("cpu-util", {}) or {}
    ap_policy = info.get("ap-policy", {}) or {}
    return {
        "identity":        identity.get("name"),
        "model":           sysinfo.get("model"),
        "firmware_version": sysinfo.get("version"),
        "uptime_seconds":  sysinfo.get("uptime"),
        "max_aps":         sysinfo.get("maxap"),
        "cpu_load_percent": cpu.get("now"),
        "master_ap_mac":   ap_policy.get("prefer-master"),
    }


# ── Tools ─────────────────────────────────────────────────────────────────────

TOOLS = [
    # ── Мониторинг ────────────────────────────────────────────────────────────
    {"name": "get_system_info",     "description": "Общая информация о сети Unleashed: версия прошивки, число AP, режим работы, мастер-AP.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_aps",             "description": "Список всех точек доступа: модель, IP, MAC, статус, uptime, каналы 2.4/5 GHz, клиенты, мощность TX.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_ap_stats",        "description": "Расширенная статистика по AP: трафик rx/tx байт, загрузка канала, клиенты по радио.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_ap_groups",       "description": "Список групп точек доступа и их настройки.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_mesh_info",       "description": "Информация о mesh сети: root AP, member AP, uplink, RSSI backhaul.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_active_clients",  "description": "Список подключённых клиентов: hostname, MAC, IP, SSID, AP, RSSI, VLAN, трафик, uptime.", "inputSchema": {"type": "object", "properties": {"ssid": {"type": "string", "description": "Фильтр по SSID (опционально)"}, "ap_name": {"type": "string", "description": "Фильтр по имени AP (опционально)"}}, "required": []}},
    {"name": "get_wlans",           "description": "Список всех SSID/WLAN: имя, статус, безопасность, VLAN.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_wlan_groups",     "description": "Список групп WLAN.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_vap_stats",       "description": "Статистика по VAP (Virtual Access Point): трафик и клиенты по каждому SSID на каждой AP.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_alarms",          "description": "Последние аварии: тип, severity, описание, время (макс 30).", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "description": "Максимум записей (по умолчанию 20, макс 30)", "default": 20}}, "required": []}},
    {"name": "get_all_events",      "description": "Все события сети: подключения, отключения, ошибки, роуминг.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "description": "Максимум записей (по умолчанию 50, макс 200)", "default": 50}}, "required": []}},
    {"name": "get_ap_events",       "description": "События конкретной точки доступа.", "inputSchema": {"type": "object", "properties": {"mac": {"type": "string", "description": "MAC точки доступа"}, "limit": {"type": "integer", "description": "Максимум записей (по умолчанию 30)", "default": 30}}, "required": []}},
    {"name": "get_wlan_events",     "description": "События конкретного SSID/WLAN.", "inputSchema": {"type": "object", "properties": {"ssid": {"type": "string", "description": "Имя SSID"}, "limit": {"type": "integer", "description": "Максимум записей (по умолчанию 30)", "default": 30}}, "required": []}},
    {"name": "get_syslog",          "description": "Системный лог Unleashed.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "description": "Максимум строк (по умолчанию 50)", "default": 50}}, "required": []}},
    {"name": "get_rogues",          "description": "Список чужих точек доступа (rogue AP) в эфире.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_blocked_clients", "description": "Список заблокированных клиентов (чёрный список MAC).", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_dpsks",           "description": "Список динамических PSK ключей (DPSK).", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_acls",            "description": "Список ACL (Access Control Lists) и их членов.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "debug_api_methods",   "description": "Показать все доступные методы aioruckus API.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    # ── Управление AP ─────────────────────────────────────────────────────────
    {"name": "reboot_ap",           "description": "Перезагрузить точку доступа по MAC. Формат: 8c:fe:74:39:c2:e0", "inputSchema": {"type": "object", "properties": {"mac": {"type": "string", "description": "MAC-адрес AP"}}, "required": ["mac"]}},
    {"name": "show_ap_leds",        "description": "Включить LED индикаторы на точке доступа по MAC.", "inputSchema": {"type": "object", "properties": {"mac": {"type": "string", "description": "MAC-адрес AP"}}, "required": ["mac"]}},
    {"name": "hide_ap_leds",        "description": "Выключить LED индикаторы на точке доступа по MAC.", "inputSchema": {"type": "object", "properties": {"mac": {"type": "string", "description": "MAC-адрес AP"}}, "required": ["mac"]}},
    # ── Управление WLAN ───────────────────────────────────────────────────────
    {"name": "enable_wlan",         "description": "Включить SSID по имени.", "inputSchema": {"type": "object", "properties": {"ssid": {"type": "string"}}, "required": ["ssid"]}},
    {"name": "disable_wlan",        "description": "Выключить SSID по имени (клиенты будут отключены).", "inputSchema": {"type": "object", "properties": {"ssid": {"type": "string"}}, "required": ["ssid"]}},
    {"name": "set_wlan_password",   "description": "Сменить пароль WLAN по имени SSID.", "inputSchema": {"type": "object", "properties": {"ssid": {"type": "string", "description": "Имя SSID"}, "password": {"type": "string", "description": "Новый пароль (минимум 8 символов)"}}, "required": ["ssid", "password"]}},
    # ── Управление клиентами ──────────────────────────────────────────────────
    {"name": "block_client",        "description": "Заблокировать клиента по MAC-адресу.", "inputSchema": {"type": "object", "properties": {"mac": {"type": "string"}}, "required": ["mac"]}},
    {"name": "unblock_client",      "description": "Снять блокировку клиента по MAC-адресу.", "inputSchema": {"type": "object", "properties": {"mac": {"type": "string"}}, "required": ["mac"]}},
]


# ── Tool logic ────────────────────────────────────────────────────────────────

async def run_tool(name, args):
    async def _run():
        websession = await _make_session()
        async with _AjaxSession(websession, RUCKUS_HOST, RUCKUS_USER, RUCKUS_PASS,
                                 auto_cleanup_websession=True) as session:
            api = session.api

            # ── Мониторинг ────────────────────────────────────────────────────

            if name == "get_system_info":
                return _clean_system_info(await api.get_system_info(SystemStat.ALL))

            elif name == "get_aps":
                return [_clean_ap(ap) for ap in await api.get_aps()]

            elif name == "get_ap_stats":
                stats = await api.get_ap_stats()
                if isinstance(stats, list):
                    return [_obj_to_dict(x) for x in stats]
                return _obj_to_dict(stats)

            elif name == "get_ap_groups":
                groups = await api.get_ap_groups()
                if isinstance(groups, list):
                    return [_obj_to_dict(g) for g in groups]
                return _obj_to_dict(groups)

            elif name == "get_mesh_info":
                return _obj_to_dict(await api.get_mesh_info())

            elif name == "get_active_clients":
                clients = [_clean_client(c) for c in await api.get_active_clients()]
                ssid_f = args.get("ssid", "").lower()
                ap_f   = args.get("ap_name", "").lower()
                if ssid_f:
                    clients = [c for c in clients if ssid_f in (c.get("ssid") or "").lower()]
                if ap_f:
                    clients = [c for c in clients if ap_f in (c.get("ap") or "").lower()]
                return {"total": len(clients), "clients": clients}

            elif name == "get_wlans":
                result = []
                for w in await api.get_wlans():
                    w = _obj_to_dict(w)
                    enc = w.get("encryption")
                    security = enc.get("method") if isinstance(enc, dict) else (str(enc) if enc else None)
                    result.append({
                        "name":        w.get("name"),
                        "ssid":        w.get("ssid", w.get("name")),
                        "enabled":     not w.get("disabled", False),
                        "security":    security,
                        "hidden":      w.get("hidden", False),
                        "vlan":        w.get("vlan"),
                        "description": w.get("description"),
                    })
                return result

            elif name == "get_wlan_groups":
                groups = await api.get_wlan_groups()
                if isinstance(groups, list):
                    return [_obj_to_dict(g) for g in groups]
                return _obj_to_dict(groups)

            elif name == "get_vap_stats":
                stats = await api.get_vap_stats()
                if isinstance(stats, list):
                    return [_obj_to_dict(x) for x in stats]
                return _obj_to_dict(stats)

            elif name == "get_alarms":
                try:
                    limit = int(args.get("limit", 20))
                except (ValueError, TypeError):
                    limit = 20
                limit = max(1, min(limit, 30))
                alarms = await api.get_all_alarms()
                return [_clean_alarm(a) for a in alarms[:limit]]

            elif name == "get_all_events":
                try:
                    limit = int(args.get("limit", 50))
                except (ValueError, TypeError):
                    limit = 50
                limit = max(1, min(limit, 200))
                events = await api.get_all_events()
                if isinstance(events, list):
                    return [_clean_event(e) for e in events[:limit]]
                return _obj_to_dict(events)

            elif name == "get_ap_events":
                try:
                    limit = int(args.get("limit", 30))
                except (ValueError, TypeError):
                    limit = 30
                mac = args.get("mac")
                events = await api.get_ap_events()
                if isinstance(events, list):
                    if mac:
                        mac = mac.lower()
                        events = [e for e in events if mac in str(_obj_to_dict(e).get("ap", "")).lower()]
                    return [_clean_event(e) for e in events[:limit]]
                return _obj_to_dict(events)

            elif name == "get_wlan_events":
                try:
                    limit = int(args.get("limit", 30))
                except (ValueError, TypeError):
                    limit = 30
                ssid = args.get("ssid", "").lower()
                events = await api.get_wlan_events()
                if isinstance(events, list):
                    if ssid:
                        events = [e for e in events if ssid in str(_obj_to_dict(e).get("ssid", "")).lower()]
                    return [_clean_event(e) for e in events[:limit]]
                return _obj_to_dict(events)

            elif name == "get_syslog":
                try:
                    limit = int(args.get("limit", 50))
                except (ValueError, TypeError):
                    limit = 50
                log = await api.get_syslog()
                if isinstance(log, list):
                    return log[:limit]
                return _obj_to_dict(log)

            elif name == "get_rogues":
                return {
                    "active_rogues": [_clean_rogue(r) for r in await api.get_active_rogues()],
                    "known_rogues":  [_clean_rogue(r) for r in await api.get_known_rogues()],
                }

            elif name == "get_blocked_clients":
                return {"blocked_macs": await api.get_blocked_client_macs()}

            elif name == "get_dpsks":
                dpsks = await api.get_dpsks()
                if isinstance(dpsks, list):
                    return [_obj_to_dict(d) for d in dpsks]
                return _obj_to_dict(dpsks)

            elif name == "get_acls":
                acls = await api.get_acls()
                if isinstance(acls, list):
                    return [_obj_to_dict(a) for a in acls]
                return _obj_to_dict(acls)

            elif name == "debug_api_methods":
                return {"methods": sorted(x for x in dir(api) if not x.startswith("_"))}

            # ── Управление AP ──────────────────────────────────────────────────

            elif name == "reboot_ap":
                mac = _normalize_mac(_require(args, "mac"))
                await api.do_restart_ap(mac)
                return {"status": "ok", "action": "reboot_ap", "mac": mac}

            elif name == "show_ap_leds":
                mac = _normalize_mac(_require(args, "mac"))
                await api.do_show_ap_leds(mac)
                return {"status": "ok", "action": "show_ap_leds", "mac": mac}

            elif name == "hide_ap_leds":
                mac = _normalize_mac(_require(args, "mac"))
                await api.do_hide_ap_leds(mac)
                return {"status": "ok", "action": "hide_ap_leds", "mac": mac}

            # ── Управление WLAN ────────────────────────────────────────────────

            elif name == "enable_wlan":
                ssid = _require(args, "ssid")
                await api.do_enable_wlan(ssid)
                return {"status": "ok", "action": "enable_wlan", "ssid": ssid}

            elif name == "disable_wlan":
                ssid = _require(args, "ssid")
                await api.do_disable_wlan(ssid)
                return {"status": "ok", "action": "disable_wlan", "ssid": ssid}

            elif name == "set_wlan_password":
                ssid     = _require(args, "ssid")
                password = _require(args, "password")
                if len(password) < 8:
                    raise ValueError("Password must be at least 8 characters")
                await api.do_set_wlan_password(ssid, password)
                return {"status": "ok", "action": "set_wlan_password", "ssid": ssid}

            # ── Управление клиентами ───────────────────────────────────────────

            elif name == "block_client":
                mac = _normalize_mac(_require(args, "mac"))
                await api.do_block_client(mac)
                return {"status": "ok", "action": "block_client", "mac": mac}

            elif name == "unblock_client":
                mac = _normalize_mac(_require(args, "mac"))
                await api.do_unblock_client(mac)
                return {"status": "ok", "action": "unblock_client", "mac": mac}

            else:
                raise ValueError(f"Unknown tool: {name}")

    return await asyncio.wait_for(_run(), timeout=15)


# ── Auth ──────────────────────────────────────────────────────────────────────

def check_auth(request: Request):
    auth = request.headers.get("Authorization", "")
    allowed = {f"Bearer {STATIC_TOKEN}"}
    if MCP_SECRET:
        allowed.add(f"Bearer {MCP_SECRET}")
    if auth not in allowed:
        raise HTTPException(status_code=401, detail="Unauthorized")

ALLOWED_REDIRECT_HOSTS = {"claude.ai", "anthropic.com", "console.anthropic.com"}

def validate_redirect_uri(uri: str):
    from urllib.parse import urlparse
    parsed = urlparse(uri)
    host = (parsed.hostname or "").lower()
    is_local = host in ("localhost", "127.0.0.1")
    is_trusted = host in ALLOWED_REDIRECT_HOSTS or any(host.endswith("." + h) for h in ALLOWED_REDIRECT_HOSTS)
    ok = (parsed.scheme == "http" and is_local) or (parsed.scheme == "https" and (is_local or is_trusted))
    if not ok:
        raise HTTPException(status_code=400, detail=f"redirect_uri not allowed: {uri}")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "ruckus-mcp running", "version": "2.0.0", "host": RUCKUS_HOST}

@app.get("/mcp")
async def mcp_info(request: Request):
    check_auth(request)
    return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "ruckus-mcp", "version": "2.0.0"}}

@app.post("/mcp")
async def mcp_handler(request: Request):
    check_auth(request)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})

    method = body.get("method")
    req_id = body.get("id")

    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "ruckus-mcp", "version": "2.0.0"}
        }})

    elif method == "notifications/initialized":
        return Response(status_code=204)

    elif method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

    elif method == "tools/call":
        params    = body.get("params", {})
        tool_name = params.get("name")
        tool_args = params.get("arguments")
        if tool_args is None:
            tool_args = {}
        if not isinstance(tool_args, dict):
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "arguments must be an object"}})
        logger.info("Tool called: %s args=%s", tool_name, tool_args)
        try:
            result = await run_tool(tool_name, tool_args)
            logger.info("Tool OK: %s", tool_name)
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2, default=str)}],
                "isError": False
            }})
        except asyncio.TimeoutError:
            logger.error("Tool timeout: %s", tool_name)
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": "Ruckus API timeout after 15 seconds"}})
        except Exception as e:
            logger.exception("Tool failed: %s", tool_name)
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(e)}})

    else:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})


# ── OAuth stub ────────────────────────────────────────────────────────────────

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return {
        "issuer":                   f"https://{DOMAIN}",
        "authorization_endpoint":   f"https://{DOMAIN}/oauth/authorize",
        "token_endpoint":           f"https://{DOMAIN}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported":    ["authorization_code"]
    }

@app.get("/oauth/authorize")
async def oauth_authorize(request: Request):
    from fastapi.responses import RedirectResponse
    params       = dict(request.query_params)
    redirect_uri = params.get("redirect_uri", "")
    state        = params.get("state", "")
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri required")
    validate_redirect_uri(redirect_uri)
    return RedirectResponse(url=f"{redirect_uri}?code=ruckus-mcp-static-code&state={state}")

@app.post("/oauth/token")
async def oauth_token(request: Request):
    form = await request.form()
    if form.get("client_secret") != STATIC_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid client_secret")
    return {"access_token": STATIC_TOKEN, "token_type": "bearer", "expires_in": 86400}
