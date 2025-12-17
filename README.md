# TP-Link M7000/M7200 Python API

Small Python client for TP-Link M7000/M7200 MiFi devices. It fetches an auth challenge, encrypts login and follow-up calls with AES/RSA, and exposes handy commands (status, SMS, network mode, mobile data, reboot, arbitrary invokes).

## Setup
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Optional config file `m7200.ini`:
```ini
[modem]
host=192.168.0.1
username=admin
password=your_password
session_file=m7200.session.json
```

## CLI usage
All commands log in first, then call the modem API. Add `-v` for debug logs.
```bash
# Login and show result/token
python m7200.py --password YOUR_PASS login

# Status (module=status, action=0)
python m7200.py --password YOUR_PASS status

# Toggle mobile data (module=wan, action=1)
python m7200.py --password YOUR_PASS mobile-data on   # or off

# Set preferred network mode (module=wan, action=1) | 1=3G only, 2=4G only, 3=4G preferred
python m7200.py --password YOUR_PASS network-mode 3

# Send SMS (module=message, action=3)
python m7200.py --password YOUR_PASS send-sms 5555 "INTERNET"

# Read SMS inbox (module=message, action=2)
python m7200.py --password YOUR_PASS read-sms --page 1 --page-size 8 --box 0

# Current IP (module=status, action=0)
python m7200.py --password YOUR_PASS ip
python m7200.py --password YOUR_PASS ip --ipv6

# Reboot (module=reboot, action=0)
python m7200.py --password YOUR_PASS reboot

# Arbitrary invoke
python m7200.py --password YOUR_PASS invoke status 0
python m7200.py --password YOUR_PASS invoke wan 1 --data '{"networkPreferredMode":3}'
```
Flags `--host` and `--username` override config/defaults. Use `--session-file` (or `session_file` in
`m7200.ini`) to cache the session bundle and reuse it on later runs (default: `m7200.session.json`).

## Notes
- AES-CBC key/IV are generated per login (numeric strings, 16 chars). RSA is chunked to support the 512-bit modulus the modem returns.
- All requests are plain HTTP to the modem LAN IP (no TLS on the device).
- This client only implements a subset of modules/actions. See the docstring in `m7200.py` for the full list of known module/action codes.
