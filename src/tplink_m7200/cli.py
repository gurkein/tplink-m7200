import argparse
import asyncio
import json
import logging
import sys

import aiohttp

from .client import TPLinkM7200, init_client

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
    parser.add_argument("--timeout", type=float, help="Request timeout in seconds")

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


async def cli_main() -> None:
    parser = build_cli_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    async with aiohttp.ClientSession() as session:
        try:
            client, session_file = await init_client(
                session,
                host=args.host,
                username=args.username,
                password=args.password,
                config_path=args.config,
                session_file=args.session_file,
                timeout_seconds=args.timeout,
                auto_login=args.command != "login",
            )
        except ValueError as exc:
            parser.error(str(exc))

        if args.command == "login":
            result = await client.login()
            save_session_file(session_file, client.export_session())
            print(json.dumps(result, indent=2))
            return

        if args.command == "reboot":
            resp = await client.reboot()
            print(json.dumps(resp, indent=2))
        elif args.command == "invoke":
            data = json.loads(args.data) if args.data else None
            resp = await client.invoke(args.module, args.action, data)
            print(json.dumps(resp, indent=2))
        elif args.command == "send-sms":
            resp = await client.send_sms(args.number, args.text)
            print(json.dumps(resp, indent=2))
        elif args.command == "read-sms":
            resp = await client.read_sms(args.page, args.page_size, args.box)
            print(json.dumps(resp, indent=2))
        elif args.command == "status":
            resp = await client.get_status()
            print(json.dumps(resp, indent=2))
        elif args.command == "network-mode":
            resp = await client.set_network_mode(args.mode)
            print(json.dumps(resp, indent=2))
        elif args.command == "mobile-data":
            resp = await client.set_mobile_data(args.state == "on")
            print(json.dumps(resp, indent=2))
        elif args.command == "ip":
            try:
                ip_value = await client.get_ip(args.ipv6)
            except RuntimeError as exc:
                print(f"error: {exc}", file=sys.stderr)
                raise SystemExit(1)
            else:
                print(ip_value)
        elif args.command == "quota":
            try:
                quota = await client.get_quota(args.human)
            except RuntimeError as exc:
                print(f"error: {exc}", file=sys.stderr)
                raise SystemExit(1)
            else:
                print(json.dumps(quota, indent=2))


def main() -> None:
    asyncio.run(cli_main())


__all__ = ["main"]
