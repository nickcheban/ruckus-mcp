# ruckus-mcp

MCP-сервер для Ruckus Unleashed (протестировано на R500/R600, встроенный веб-сервер Embedthis-Appweb). Использует [`aioruckus`](https://github.com/gabe565/aioruckus) для общения с AJAX-API контроллера.

## Инструменты

**Мониторинг**

| Инструмент | Описание |
|---|---|
| `get_system_info` | Версия прошивки, число AP, режим работы, мастер-AP |
| `get_aps` / `get_ap_stats` / `get_ap_groups` | Точки доступа, их статистика и группы |
| `get_mesh_info` | Mesh-топология: root/member AP, RSSI backhaul |
| `get_active_clients` | Подключённые клиенты (фильтр по SSID/AP) |
| `get_wlans` / `get_wlan_groups` / `get_vap_stats` | SSID, группы WLAN, статистика VAP |
| `get_alarms` / `get_all_events` / `get_ap_events` / `get_wlan_events` / `get_syslog` | События и логи |
| `get_rogues` | Чужие точки доступа в эфире |
| `get_blocked_clients` / `get_dpsks` / `get_acls` | Блок-лист, DPSK-ключи, ACL |
| `debug_api_methods` | Список всех методов `aioruckus` — диагностический инструмент для разработки |

**Управление**

| Инструмент | Описание |
|---|---|
| `reboot_ap` / `show_ap_leds` / `hide_ap_leds` | Управление точкой доступа по MAC |
| `enable_wlan` / `disable_wlan` / `set_wlan_password` | Управление SSID |
| `block_client` / `unblock_client` | Управление клиентом по MAC |

## Установка

```bash
git clone <this-repo> ruckus-mcp && cd ruckus-mcp
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # заполните RUCKUS_HOST/USER/PASS, MCP_SECRET
uvicorn server:app --host 0.0.0.0 --port 8003
```

Systemd-юнит — пример в [`deploy/ruckus-mcp.service`](deploy/ruckus-mcp.service).

## Security model

- Авторизация — `Authorization: Bearer $MCP_SECRET` на `/mcp`. **В отличие от других серверов в этой линейке**, здесь заголовок `Authorization` обязателен всегда — даже без заданного `MCP_SECRET` нужно передать `Authorization: Bearer ` (пустое значение). Рекомендуется всегда задавать `MCP_SECRET`.
- `/.well-known/oauth-authorization-server` + `/oauth/authorize` + `/oauth/token` — совместимая заглушка для custom-коннекторов claude.ai, у которых [нет поддержки статического API-ключа](https://claude.com/docs/connectors/building/authentication) — только полноценный OAuth 2.1 или отсутствие авторизации вовсе. Реальную защиту даёт Bearer-токен на `/mcp`.
- `redirect_uri` в `/oauth/authorize` — allowlist (`claude.ai`, `anthropic.com`, `console.anthropic.com`, `localhost`).
- **Важно при доработке `get_system_info`**: `aioruckus.get_system_info(SystemStat.ALL)` отдаёт **полный сырой конфиг контроллера**, включая пароль локального админа в открытом виде, TR-069/CWMP-пароли и облачные ключи (AWS SNS, PubNub). `_clean_system_info()` в коде вайтлистит только безопасные поля — если добавляете новые поля в вывод этого инструмента, добавляйте их явно через whitelist, не расширяйте через `**info` или подобное.
- TLS-верификация к контроллеру отключена (`ssl.CERT_NONE`, `SECLEVEL=0`) — типичные Unleashed-прошивки используют самоподписанные сертификаты со слабым ключом. Это осознанный компромисс для доверенной локальной сети; не направляйте `RUCKUS_HOST` на что-либо за пределами вашего LAN/VPN.

## Требования

- Ruckus Unleashed (веб-интерфейс на 443/8443).
- Python 3.11+.

## Лицензия

MIT — см. [LICENSE](LICENSE).
