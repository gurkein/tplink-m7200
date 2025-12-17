import argparse
import asyncio
import configparser
import json
import logging
import os
import sys
import tempfile
from datetime import datetime
from typing import Any, Dict, Optional

import aiohttp

from .client import TPLinkM7200

LOGGER = logging.getLogger(__name__)


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TP-Link M7200 API helper.", add_help=True)
    parser.add_argument("--host", default=None, help="Modem host/IP (default 192.168.0.1)")
    parser.add_argument("--username", default=None, help="Username (default admin)")
    parser.add_argument("--password", default=None, help="Password (required)")
    parser.add_argument("--config", default="m7200.ini", help="Path to ini config (section [modem])")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--token", help="Existing token (if provided, skip login)")
    parser.add_argument(
        "--session-file",
        default=None,
        help="Path to session cache file (default: m7200.session.json)",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("login", help="Authenticate and print token/result")

    reboot_p = sub.add_parser("reboot", help="Login then reboot")
    reboot_p.add_argument("--token", help="Existing token (if provided, skip login)")

    invoke_p = sub.add_parser("invoke", help="Login then call arbitrary module/action")
    invoke_p.add_argument("module")
    invoke_p.add_argument("action", type=int)
    invoke_p.add_argument("--data", help="JSON payload for data field")

    send_p = sub.add_parser("send-sms", help="Send an SMS (module=message, action=3)")
    send_p.add_argument("number", help="Destination phone number")
    send_p.add_argument("text", help="SMS body text")

    read_p = sub.add_parser("read-sms", help="Read SMS box (module=message, action=2)")
    read_p.add_argument("--page", type=int, default=1, help="Page number (default: 1)")
    read_p.add_argument("--page-size", type=int, default=8, help="Messages per page (default: 8)")
    read_p.add_argument("--box", type=int, default=0, help="Box type: 0=inbox,1=outbox,2=draft (default: 0)")

    net_p = sub.add_parser("network-mode", help="Set preferred network mode (module=wan, action=1 saveConfig)")
    net_p.add_argument(
        "mode",
        type=int,
        choices=[1, 2, 3],
        help="Network preferred mode: 1=3G only, 2=4G only, 3=4G preferred",
    )

    sub.add_parser("status", help="Login then fetch status (module=status, action=0)")

    data_p = sub.add_parser("mobile-data", help="Toggle mobile data (module=wan, action=1 saveConfig)")
    data_p.add_argument("state", choices=["on", "off"], help="Turn mobile data on/off")

    ip_p = sub.add_parser("ip", help="Fetch current IP (module=status, action=0)")
    ip_p.add_argument("--ipv6", action="store_true", help="Return IPv6 address instead of IPv4")

    quota_p = sub.add_parser("quota", help="Fetch data quota/usage (module=status, action=0)")
    quota_p.add_argument("--human", action="store_true", help="Format byte values with units")
    return parser


def load_config(path: str) -> Dict[str, Any]:
    config = configparser.ConfigParser()
    if not os.path.exists(path):
        return {}
    config.read(path)
    modem_cfg = config["modem"] if "modem" in config else {}
    return {
        "host": modem_cfg.get("host"),
        "username": modem_cfg.get("username"),
        "password": modem_cfg.get("password"),
        "session_file": modem_cfg.get("session_file"),
    }


def extract_wan_ip(status: Dict[str, Any], ipv6: bool) -> Optional[str]:
    wan = status.get("wan")
    if not isinstance(wan, dict):
        return None
    key = "ipv6" if ipv6 else "ipv4"
    value = wan.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _parse_bytes(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return None
    return None


def _parse_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
    return None


def _format_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    size = float(value)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} EiB"


def extract_quota(status: Dict[str, Any], human: bool) -> Optional[Dict[str, Any]]:
    wan = status.get("wan")
    if not isinstance(wan, dict):
        return None
    enable_data_limit = _parse_bool(wan.get("enableDataLimit"))
    fields = {
        "totalStatistics": wan.get("totalStatistics"),
        "dailyStatistics": wan.get("dailyStatistics"),
        "limitation": wan.get("limitation"),
    }
    parsed = {key: _parse_bytes(value) for key, value in fields.items()}
    total = parsed["totalStatistics"]
    limit = parsed["limitation"]
    if human:
        formatted = {
            key: (_format_bytes(value) if isinstance(value, int) else None)
            for key, value in parsed.items()
        }
        result: Dict[str, Any] = {
            "total": formatted["totalStatistics"],
            "daily": formatted["dailyStatistics"],
            "limitation": formatted["limitation"],
            "enable_data_limit": enable_data_limit,
            "data_limit": wan.get("dataLimit"),
            "enable_payment_day": _parse_bool(wan.get("enablePaymentDay")),
        }
        if enable_data_limit is True and isinstance(total, int) and isinstance(limit, int):
            result["remaining"] = _format_bytes(max(limit - total, 0))
        return result
    result = {
        "total": parsed["totalStatistics"],
        "daily": parsed["dailyStatistics"],
        "limitation": parsed["limitation"],
        "enable_data_limit": enable_data_limit,
        "data_limit": wan.get("dataLimit"),
        "enable_payment_day": _parse_bool(wan.get("enablePaymentDay")),
    }
    if enable_data_limit is True and isinstance(total, int) and isinstance(limit, int):
        result["remaining"] = max(limit - total, 0)
    return result


def load_session_file(path: str) -> Optional[Dict[str, Any]]:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def save_session_file(path: str, data: Dict[str, Any]) -> None:
    if not path:
        return
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".m7200_session_", dir=directory or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


async def cli_main() -> None:
    parser = build_cli_parser()
    args = parser.parse_args()

    cfg = load_config(args.config)
    host = args.host or cfg.get("host") or "192.168.0.1"
    username = args.username or cfg.get("username") or "admin"
    password = args.password or cfg.get("password")
    session_file = args.session_file or cfg.get("session_file") or "m7200.session.json"
    if password is None:
        parser.error("Password must be provided via --password or config [modem].password")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    async with aiohttp.ClientSession() as session:
        client = TPLinkM7200(host, username, password, session)
        session_data = load_session_file(session_file)
        if session_data:
            if session_data.get("host") == host and session_data.get("username") == username:
                client.import_session(session_data)
            else:
                LOGGER.debug("Session file does not match host/username, ignoring.")
                session_data = None

        if args.command == "login":
            result = await client.login()
            save_session_file(session_file, client.export_session())
            print(json.dumps(result, indent=2))
            return

        if args.command in (
            "invoke",
            "reboot",
            "send-sms",
            "read-sms",
            "status",
            "network-mode",
            "mobile-data",
            "ip",
            "quota",
        ):
            if args.token:
                client.token = args.token
            elif session_data:
                valid = await client.validate_session()
                if not valid:
                    client.clear_session()
            if not client.token or not client.aes_key or not client.aes_iv:
                await client.login()
                save_session_file(session_file, client.export_session())

        if args.command == "reboot":
            resp = await client.reboot()
            print(json.dumps(resp, indent=2))
        elif args.command == "invoke":
            data = json.loads(args.data) if args.data else None
            resp = await client.invoke(args.module, args.action, data)
            print(json.dumps(resp, indent=2))
        elif args.command == "send-sms":
            send_time = datetime.now().strftime("%Y,%m,%d,%H,%M,%S")
            payload = {"sendMessage": {"to": args.number, "textContent": args.text, "sendTime": send_time}}
            resp = await client.invoke("message", 3, payload)
            print(json.dumps(resp, indent=2))
        elif args.command == "read-sms":
            payload = {
                "pageNumber": args.page,
                "amountPerPage": args.page_size,
                "box": args.box,
            }
            resp = await client.invoke("message", 2, payload)
            print(json.dumps(resp, indent=2))
        elif args.command == "status":
            resp = await client.invoke("status", 0, None)
            print(json.dumps(resp, indent=2))
        elif args.command == "network-mode":
            resp = await client.invoke("wan", 1, {"networkPreferredMode": args.mode})
            print(json.dumps(resp, indent=2))
        elif args.command == "mobile-data":
            payload = {"dataSwitchStatus": args.state == "on"}
            resp = await client.invoke("wan", 1, payload)
            print(json.dumps(resp, indent=2))
        elif args.command == "ip":
            resp = await client.invoke("status", 0, None)
            ip_value = extract_wan_ip(resp, args.ipv6)
            if not ip_value:
                print("error: IP address not available in status response", file=sys.stderr)
                raise SystemExit(1)
            print(ip_value)
        elif args.command == "quota":
            resp = await client.invoke("status", 0, None)
            quota = extract_quota(resp, args.human)
            if quota is None:
                print("error: quota data not available in status response", file=sys.stderr)
                raise SystemExit(1)
            print(json.dumps(quota, indent=2))


def main() -> None:
    asyncio.run(cli_main())


__all__ = ["main"]
