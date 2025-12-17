"""TP-Link M7200 client with simple CLI.

Modules/actions (reference from device docs/observed API):
alg: getConfig=0, setConfig=1
apBridge: getConfig=0, setConfig=1, connectAp=2, scanAp=3, checkConnStatus=4
authenticator: load=0, login=1, getAttempt=2, logout=3, update=4
connectedDevices: getConfig=0, editName=1
dmz: getConfig=0, setConfig=1
flowstat: getConfig=0, setConfig=1
lan: getConf=0, setConf=1
log: getLog=0, clearLog=1, saveLog=2, refresh=3, setMdLog=4, getMdLog=5
macFilters: getBlack=0, setBlack=1
message: getConfig=0, setConfig=1, readMsg=2, sendMsg=3, saveMsg=4, delMsg=5, markRead=6, getSendStatus=7
portTriggering: getConfig=0, setConfig=1, delPT=2
powerSave: getConfig=0, setConfig=1
restoreConf: restoreConf=0
reboot: reboot=0, powerOff=1
simLock: getConfig=0, enablePin=1, disablePin=2, updatePin=3, unlockPin=4, unlockPuk=5, autoUnlock=6
status: getStatus=0
storageShare: getConf=0, setConf=1
time: getConf=0, saveConf=1, queryTime=2
update: getConfig=0, checkNew=1, serverUpdate=2, pauseLoad=3, reqLoadPercentage=4, checkUploadResult=5, startUpgrade=6,
        clearCache=7, ignoredFW=8, remindMe=9, upgradeNow=10
upnp: getConfig=0, setConfig=1, getUpnpDevList=2
virtualServer: getConfig=0, setConfig=1, delVS=2
voice: getConfig=0, sendUssd=1, cancelUssd=2, getSendStatus=3
wan: getConfig=0, saveConfig=1, addProfile=2, deleteProfile=3, wzdAddProfile=7, setNetworkSelectionMode=8,
     quaryAvailabelNetwork=9, getNetworkSelectionStatus=10, getDisconnectReason=11, cancelSearch=14, updateISP=15,
     bandSearch=16, getBandSearchStatus=17, setSelectedBand=18, cancelBandSearch=19
webServer: getLang=0, setLang=1, keepAlive=2, unsetDefault=3, getModuleList=4, getFeatureList=5, getWithoutAuthInfo=6
wlan: getConfig=0, setConfig=1, setNoneWlan=2
wps: get=0, set=1, start=2, cancel=3
"""

import argparse
import asyncio
import base64
import binascii
import configparser
import hashlib
import json
import logging
import os
import random
import sys
import tempfile
from datetime import UTC, datetime
from typing import Any, Dict, Optional

import aiohttp
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import Padding

LOGGER = logging.getLogger(__name__)

# Payload templates
CHALLENGE_PAYLOAD = {"module": "authenticator", "action": 0}
LOGIN_TEMPLATE = {"module": "authenticator", "action": 1}


# ---------- Small helpers ----------
def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def random_numeric(length: int = 16) -> str:
    return "".join(str(random.randint(0, 9)) for _ in range(length))


def aes_encrypt_b64(plaintext: str, key_bytes: bytes, iv_bytes: bytes) -> str:
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
    padded = Padding.pad(plaintext.encode("utf-8"), AES.block_size, style="pkcs7")
    return base64.b64encode(cipher.encrypt(padded)).decode("ascii")


def aes_decrypt_b64(data_b64: str, key_bytes: bytes, iv_bytes: bytes) -> str:
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
    raw = base64.b64decode(data_b64)
    plaintext = cipher.decrypt(raw)
    return Padding.unpad(plaintext, AES.block_size, style="pkcs7").decode("utf-8")


def rsa_encrypt_hex(message: str, modulus_hex: str, exponent_hex: str) -> str:
    """Chunked RSA PKCS1 v1.5 encrypt to handle 512-bit keys."""
    n = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    key = RSA.construct((n, e))
    cipher = PKCS1_v1_5.new(key)
    block_size = key.size_in_bytes() - 11  # PKCS1 v1.5 padding overhead
    msg_bytes = message.encode("utf-8")
    chunks = []
    for i in range(0, len(msg_bytes), block_size):
        chunk = msg_bytes[i : i + block_size]
        chunks.append(cipher.encrypt(chunk))
    return b"".join(chunks).hex()


# ---------- Core client ----------
class SessionDecryptionError(RuntimeError):
    """Raised when a response cannot be decrypted with current session keys."""


class TPLinkM7200:
    def __init__(self, host: str, username: str, password: str, session: aiohttp.ClientSession):
        self.host = host
        self.username = username
        self.password = password
        self.session = session

        self.seq_num: Optional[int] = None
        self.rsa_mod: Optional[str] = None
        self.rsa_pub: str = "010001"
        self.aes_key: Optional[bytes] = None
        self.aes_iv: Optional[bytes] = None
        self.token: Optional[str] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}"

    async def _post_json(self, path: str, body: Dict[str, Any]) -> str:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json", "Referer": f"{self.base_url}/"}
        data = json.dumps(body, separators=(",", ":"))
        LOGGER.debug("POST %s body=%s", url, data)
        async with self.session.post(url, data=data, headers=headers) as resp:
            text = await resp.text()
            LOGGER.debug("Response %s body=%s", resp.status, text)
            resp.raise_for_status()
            return text

    async def fetch_challenge(self) -> Dict[str, Any]:
        payload = {"data": base64.b64encode(json.dumps(CHALLENGE_PAYLOAD, separators=(",", ":")).encode("utf-8")).decode("ascii")}
        text = await self._post_json("/cgi-bin/auth_cgi", payload)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            decoded = base64.b64decode(text)
            LOGGER.debug("Decoded base64 challenge=%s", decoded)
            return json.loads(decoded)

    def _build_login_payload(self, challenge: Dict[str, Any]) -> Dict[str, str]:
        nonce = challenge["nonce"]
        self.seq_num = int(challenge["seqNum"])
        self.rsa_mod = challenge["rsaMod"]
        if challenge.get("rsaPubKey"):
            self.rsa_pub = challenge["rsaPubKey"]

        digest = md5_hex(f"{self.password}:{nonce}")
        hash_hex = md5_hex(f"{self.username}{self.password}")

        key_str = random_numeric(16)
        iv_str = random_numeric(16)
        self.aes_key = key_str.encode("utf-8")
        self.aes_iv = iv_str.encode("utf-8")

        login_body = LOGIN_TEMPLATE.copy()
        login_body["digest"] = digest
        plaintext = json.dumps(login_body, separators=(",", ":"))
        encrypted_data = aes_encrypt_b64(plaintext, self.aes_key, self.aes_iv)

        sign_query = f"key={key_str}&iv={iv_str}&h={hash_hex}&s={self.seq_num + len(encrypted_data)}"
        sign_hex = rsa_encrypt_hex(sign_query, self.rsa_mod, self.rsa_pub)

        LOGGER.debug(
            "Login plaintext=%s key=%s iv=%s seq=%s len=%s sign=%s",
            plaintext,
            key_str,
            iv_str,
            self.seq_num,
            len(encrypted_data),
            sign_query,
        )

        return {"data": encrypted_data, "sign": sign_hex}

    async def login(self) -> Dict[str, Any]:
        challenge = await self.fetch_challenge()
        payload = self._build_login_payload(challenge)
        text = await self._post_json("/cgi-bin/auth_cgi", payload)
        # Decrypt response with login key/iv
        decrypted = aes_decrypt_b64(text, self.aes_key, self.aes_iv)
        LOGGER.debug("Login decrypted=%s", decrypted)
        data = json.loads(decrypted)
        self.token = data.get("token")
        return data

    def export_session(self) -> Dict[str, Any]:
        self._ensure_session()
        assert self.aes_key is not None
        assert self.aes_iv is not None
        assert self.rsa_mod is not None
        created_at = datetime.now(UTC).isoformat(timespec="seconds")
        created_at = created_at.replace("+00:00", "Z")
        return {
            "version": 1,
            "created_at": created_at,
            "host": self.host,
            "username": self.username,
            "token": self.token,
            "rsa_mod": self.rsa_mod,
            "rsa_pub": self.rsa_pub,
            "seq_num": self.seq_num,
            "aes_key_b64": base64.b64encode(self.aes_key).decode("ascii"),
            "aes_iv_b64": base64.b64encode(self.aes_iv).decode("ascii"),
        }

    def import_session(self, data: Dict[str, Any]) -> None:
        self.token = data.get("token")
        self.rsa_mod = data.get("rsa_mod")
        self.rsa_pub = data.get("rsa_pub", self.rsa_pub)
        self.seq_num = data.get("seq_num")
        aes_key_b64 = data.get("aes_key_b64")
        aes_iv_b64 = data.get("aes_iv_b64")
        if aes_key_b64 and aes_iv_b64:
            try:
                self.aes_key = base64.b64decode(aes_key_b64)
                self.aes_iv = base64.b64decode(aes_iv_b64)
            except (binascii.Error, ValueError):
                self.aes_key = None
                self.aes_iv = None

    def clear_session(self) -> None:
        self.seq_num = None
        self.rsa_mod = None
        self.aes_key = None
        self.aes_iv = None
        self.token = None

    def _ensure_session(self) -> None:
        if not self.token or not self.aes_key or not self.aes_iv or self.seq_num is None:
            raise RuntimeError("Client not authenticated. Call login() first.")

    async def invoke(self, module: str, action: int, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generic call to /cgi-bin/web_cgi (after login)."""
        self._ensure_session()
        payload = {"token": self.token, "module": module, "action": action}
        if data is not None:
            payload.update(data)

        plaintext = json.dumps(payload, separators=(",", ":"))
        encrypted = aes_encrypt_b64(plaintext, self.aes_key, self.aes_iv)
        hash_hex = md5_hex(f"{self.username}{self.password}")
        sign_query = f"h={hash_hex}&s={self.seq_num + len(encrypted)}"
        sign_hex = rsa_encrypt_hex(sign_query, self.rsa_mod, self.rsa_pub)

        LOGGER.debug("Invoke plaintext=%s len=%s sign=%s", plaintext, len(encrypted), sign_query)

        text = await self._post_json("/cgi-bin/web_cgi", {"data": encrypted, "sign": sign_hex})
        try:
            decrypted = aes_decrypt_b64(text, self.aes_key, self.aes_iv)
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            raise SessionDecryptionError("Failed to decrypt response; session may be invalid.") from exc
        LOGGER.debug("Invoke decrypted=%s", decrypted)
        return json.loads(decrypted)

    async def reboot(self) -> Dict[str, Any]:
        """Reboot device using module 'reboot', action 0."""
        return await self.invoke("reboot", 0)

    async def validate_session(self) -> bool:
        try:
            response = await self.invoke("webServer", 2)
        except Exception:
            return False
        return _is_success_response(response)


# ---------- CLI ----------
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


def _is_success_response(response: Dict[str, Any]) -> bool:
    for key in ("errorCode", "errCode", "error_code"):
        if key in response:
            return response.get(key) == 0
    return True


def extract_wan_ip(status: Dict[str, Any], ipv6: bool) -> Optional[str]:
    wan = status.get("wan")
    if not isinstance(wan, dict):
        return None
    key = "ipv6" if ipv6 else "ipv4"
    value = wan.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


async def invoke_with_reauth(
    client: TPLinkM7200,
    session_file: str,
    module: str,
    action: int,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    try:
        return await client.invoke(module, action, data)
    except SessionDecryptionError:
        LOGGER.warning("Session decrypt failed; re-authenticating.")
        client.clear_session()
        await client.login()
        save_session_file(session_file, client.export_session())
        return await client.invoke(module, action, data)


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

        # For invoke/reboot, try to reuse provided token; otherwise login first.
        if args.command in (
            "invoke",
            "reboot",
            "send-sms",
            "read-sms",
            "status",
            "network-mode",
            "mobile-data",
            "ip",
        ):
            if args.token:
                client.token = args.token
                # Need challenge to set RSA, seq, and AES keys, so perform login anyway.
            elif session_data:
                valid = await client.validate_session()
                if not valid:
                    client.clear_session()
            if not client.token or not client.aes_key or not client.aes_iv:
                await client.login()
                save_session_file(session_file, client.export_session())

        if args.command == "reboot":
            resp = await invoke_with_reauth(client, session_file, "reboot", 0)
            print(json.dumps(resp, indent=2))
        elif args.command == "invoke":
            data = json.loads(args.data) if args.data else None
            resp = await invoke_with_reauth(client, session_file, args.module, args.action, data)
            print(json.dumps(resp, indent=2))
        elif args.command == "send-sms":
            # UI payload example: {"sendMessage":{"to":"5555","textContent":"INTERNET","sendTime":"2025,12,16,14,27,19"}}
            send_time = datetime.now().strftime("%Y,%m,%d,%H,%M,%S")
            payload = {"sendMessage": {"to": args.number, "textContent": args.text, "sendTime": send_time}}
            resp = await invoke_with_reauth(client, session_file, "message", 3, payload)
            print(json.dumps(resp, indent=2))
        elif args.command == "read-sms":
            payload = {
                "pageNumber": args.page,
                "amountPerPage": args.page_size,
                "box": args.box,
            }
            resp = await invoke_with_reauth(client, session_file, "message", 2, payload)
            print(json.dumps(resp, indent=2))
        elif args.command == "status":
            resp = await invoke_with_reauth(client, session_file, "status", 0, None)
            print(json.dumps(resp, indent=2))
        elif args.command == "network-mode":
            resp = await invoke_with_reauth(client, session_file, "wan", 1, {"networkPreferredMode": args.mode})
            print(json.dumps(resp, indent=2))
        elif args.command == "mobile-data":
            payload = {"dataSwitchStatus": args.state == "on"}
            resp = await invoke_with_reauth(client, session_file, "wan", 1, payload)
            print(json.dumps(resp, indent=2))
        elif args.command == "ip":
            resp = await invoke_with_reauth(client, session_file, "status", 0, None)
            ip_value = extract_wan_ip(resp, args.ipv6)
            if not ip_value:
                print("error: IP address not available in status response", file=sys.stderr)
                raise SystemExit(1)
            print(ip_value)


if __name__ == "__main__":
    asyncio.run(cli_main())
