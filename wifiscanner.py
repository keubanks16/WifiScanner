#!/usr/bin/env python3
"""
WifiScanner - find the devices on your WiFi network and flag likely cameras.

Runs on Windows, Linux and (if you ever need it) macOS with plain Python 3.8+.
No extra packages required.

What it does
  1. Works out your network (e.g. 192.168.1.0/24) from your own IP.
  2. Sweeps every address with ping + quick TCP probes to wake devices up.
  3. Reads your computer's ARP table to get each device's MAC address.
  4. Looks up the maker of each MAC (IEEE vendor list, cached locally).
  5. Sends ONVIF (WS-Discovery) and UPnP (SSDP) discovery broadcasts -
     most IP cameras answer these.
  6. Checks camera-typical ports (RTSP 554, Hikvision 8000, Dahua 37777,
     XMeye 34567, Tuya 6668 ...), grabs web page titles / server banners.
  7. Scores every device and labels it CAMERA, POSSIBLE CAMERA or OTHER.
  8. Prints a table and saves an HTML report you can open in any browser.

Only scan networks you own or have permission to scan.

Usage
  python wifiscanner.py                      # scan your current network
  python wifiscanner.py --cameras            # show only likely cameras
  python wifiscanner.py --find ring --find wyze   # look for certain devices
  python wifiscanner.py --network 192.168.0.0/24
  python wifiscanner.py --no-report          # skip the HTML report
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as _dt
import html
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from dataclasses import dataclass, field, asdict
from pathlib import Path

VERSION = "1.0.0"
IS_WINDOWS = platform.system() == "Windows"
HERE = Path(__file__).resolve().parent
OUI_CACHE = HERE / "oui_cache.json"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

# --------------------------------------------------------------------------
# Camera knowledge
# --------------------------------------------------------------------------

# Words that, when they show up in a vendor name, hostname, web page title,
# UPnP description or banner, point to a camera / NVR / doorbell.
CAMERA_BRANDS = {
    "hikvision": "Hikvision", "hangzhou hikvision": "Hikvision",
    "dahua": "Dahua", "zhejiang dahua": "Dahua",
    "axis communications": "Axis", "reolink": "Reolink",
    "amcrest": "Amcrest", "wyze": "Wyze", "ring": "Ring",
    "arlo": "Arlo", "netgear arlo": "Arlo", "eufy": "eufy",
    "foscam": "Foscam", "shenzhen foscam": "Foscam",
    "uniview": "Uniview", "zhejiang uniview": "Uniview",
    "hanwha": "Hanwha/Wisenet", "wisenet": "Hanwha/Wisenet",
    "samsung techwin": "Hanwha/Wisenet", "lorex": "Lorex",
    "swann": "Swann", "ezviz": "EZVIZ", "annke": "ANNKE",
    "vivotek": "Vivotek", "mobotix": "Mobotix", "bosch security": "Bosch",
    "geovision": "GeoVision", "milesight": "Milesight", "tiandy": "Tiandy",
    "xiongmai": "Xiongmai", "hangzhou xiongmai": "Xiongmai",
    "imou": "Imou", "blink": "Blink", "immedia": "Blink",
    "simplisafe": "SimpliSafe", "canary": "Canary", "geeni": "Geeni",
    "merkury": "Merkury/Geeni", "yi technology": "YI", "kami": "Kami/YI",
    "tapo": "TP-Link Tapo", "vstarcam": "VStarcam", "sricam": "Sricam",
    "wansview": "Wansview", "zmodo": "Zmodo", "night owl": "Night Owl",
    "q-see": "Q-See", "defender": "Defender", "ipcam": "IP camera",
    "ip camera": "IP camera", "ipc": "IP camera", "nvr": "NVR",
    "dvr": "DVR", "netcam": "IP camera", "webcam": "Webcam",
    "doorbell": "Doorbell", "camera": "Camera", "onvif": "ONVIF",
}

# Makers that build cameras *and* lots of other things (plugs, speakers,
# routers). A match here is a hint, not proof.
MAYBE_CAMERA_VENDORS = {
    "espressif": "Espressif (cheap smart devices / cams)",
    "tuya": "Tuya (smart-home, many cams)",
    "hangzhou tuya": "Tuya (smart-home, many cams)",
    "tp-link": "TP-Link (Tapo cams, plugs, routers)",
    "amazon": "Amazon (Ring/Blink/Echo)",
    "google": "Google (Nest cams, speakers)",
    "nest labs": "Google Nest",
    "anker": "Anker (eufy cams)",
    "ubiquiti": "Ubiquiti (UniFi Protect cams)",
    "realtek": "Realtek (many cheap cams)",
    "ingenic": "Ingenic (camera chips)",
    "sigmastar": "SigmaStar (camera chips)",
    "novatek": "Novatek (camera chips)",
    "beken": "Beken (cheap smart devices)",
    "shenzhen": "Shenzhen-based maker",
    "xiaomi": "Xiaomi (Mi cams)",
    "chuango": "Chuango", "vtech": "VTech (baby monitors)",
    "motorola": "Motorola (baby monitors)",
}

# Port -> (label, camera score, is a strong camera signal)
PORTS = {
    554:   ("RTSP video stream", 45, True),
    8554:  ("RTSP (alt)", 40, True),
    10554: ("RTSP (alt)", 35, True),
    37777: ("Dahua / Amcrest service", 50, True),
    37778: ("Dahua / Amcrest UDP-TCP", 40, True),
    34567: ("XMeye / cheap DVR-NVR", 50, True),
    8000:  ("Hikvision SDK", 30, True),
    9000:  ("Reolink / DVR media", 20, False),
    6668:  ("Tuya local control", 15, False),
    1935:  ("RTMP streaming", 15, False),
    8899:  ("ONVIF (alt)", 25, True),
    2020:  ("ONVIF (Tapo)", 25, True),
    5000:  ("UPnP / web", 0, False),
    80:    ("Web page", 0, False),
    443:   ("Web page (HTTPS)", 0, False),
    8080:  ("Web page (alt)", 0, False),
    8443:  ("Web page (alt HTTPS)", 0, False),
    81:    ("Web page (cam alt)", 5, False),
    22:    ("SSH", 0, False),
    23:    ("Telnet (insecure!)", 5, False),
    53:    ("DNS (router?)", -10, False),
    139:   ("Windows sharing", -20, False),
    445:   ("Windows sharing", -20, False),
    548:   ("Apple file sharing", -20, False),
    62078: ("iPhone/iPad sync", -40, False),
    3389:  ("Remote Desktop (PC)", -30, False),
    9100:  ("Printer", -30, False),
    631:   ("Printer (IPP)", -30, False),
    8009:  ("Chromecast / Google TV", -20, False),
    7000:  ("AirPlay", -20, False),
}

WAKE_PORTS = [80, 443, 554, 8000, 62078, 445]


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    open_ports: list = field(default_factory=list)
    titles: list = field(default_factory=list)
    upnp: list = field(default_factory=list)
    onvif: bool = False
    rtsp_ok: bool = False
    is_self: bool = False
    is_gateway: bool = False
    score: int = 0
    reasons: list = field(default_factory=list)
    label: str = "OTHER"
    brand_guess: str = ""

    @property
    def sort_key(self):
        return tuple(int(p) for p in self.ip.split("."))


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def log(msg: str, quiet: bool = False):
    if not quiet:
        print(msg, flush=True)


def norm_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) != 6:
        return ""
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return ""


def is_random_mac(mac: str) -> bool:
    """Phones and laptops often use a private/random MAC (2nd hex digit 2/6/A/E)."""
    if not mac:
        return False
    return mac[1] in "26ae"


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is actually sent
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def run(cmd: list, timeout: float = 10) -> str:
    try:
        flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        out = subprocess.run(cmd, capture_output=True, timeout=timeout,
                             creationflags=flags)
        return out.stdout.decode(errors="ignore")
    except (OSError, subprocess.TimeoutExpired):
        return ""


def default_gateway() -> str:
    if IS_WINDOWS:
        out = run(["route", "print", "-4", "0.0.0.0"])
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""
    out = run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    out = run(["netstat", "-rn"])
    m = re.search(r"^(?:default|0\.0\.0\.0)\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
    return m.group(1) if m else ""


def own_mac() -> str:
    node = uuid.getnode()
    return ":".join(f"{(node >> s) & 0xff:02x}" for s in range(40, -1, -8))


# --------------------------------------------------------------------------
# MAC vendor lookup
# --------------------------------------------------------------------------

def load_oui(refresh: bool = False, quiet: bool = False) -> dict:
    if OUI_CACHE.exists() and not refresh:
        try:
            return json.loads(OUI_CACHE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    log("  Downloading MAC vendor list from IEEE (one time, ~5 MB)...", quiet)
    try:
        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "WifiScanner"})
        with urllib.request.urlopen(req, timeout=60) as r:
            text = r.read().decode("utf-8", errors="ignore")
    except OSError as e:
        log(f"  Couldn't download vendor list ({e}). Vendors will show as unknown.", quiet)
        return {}
    table = {}
    for line in text.splitlines():
        m = re.match(r"\s*([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)", line)
        if m:
            table[m.group(1).replace("-", ":").lower()] = m.group(2).strip()
    try:
        OUI_CACHE.write_text(json.dumps(table), encoding="utf-8")
    except OSError:
        pass
    return table


def vendor_for(mac: str, oui: dict) -> str:
    if not mac:
        return ""
    if is_random_mac(mac):
        return "(private/random MAC - usually a phone or laptop)"
    return oui.get(mac[:8], "")


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def ping(ip: str, timeout_ms: int) -> bool:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    out = run(cmd, timeout=timeout_ms / 1000 + 2)
    return "ttl=" in out.lower()


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def wake(ip: str, timeout_ms: int) -> bool:
    """Ping, then knock on a few ports. Any answer means the host is up.
    Even a refused TCP connection fills the ARP table, which is what we want."""
    if ping(ip, timeout_ms):
        return True
    for p in WAKE_PORTS:
        try:
            with socket.create_connection((ip, p), timeout=0.3):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            pass
    return False


def read_arp() -> dict:
    """Return {ip: mac} from the OS ARP / neighbour table."""
    found = {}
    text = run(["arp", "-a"])
    if not IS_WINDOWS:
        text += "\n" + run(["ip", "neigh"])
        try:
            text += "\n" + Path("/proc/net/arp").read_text()
        except OSError:
            pass
    pat = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})\D+?"
        r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
    for line in text.splitlines():
        m = pat.search(line)
        if not m:
            continue
        mac = norm_mac(m.group(2))
        if mac and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") \
                and not mac.startswith("01:00:5e"):
            found[m.group(1)] = mac
    return found


def ws_discovery(wait: float = 3.0) -> set:
    """ONVIF cameras answer this multicast probe. Returns their IPs."""
    msg = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<e:Header><w:MessageID>uuid:' + str(uuid.uuid4()) + '</w:MessageID>'
        '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action e:mustUnderstand="true">'
        'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
        '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>'
        '</d:Probe></e:Body></e:Envelope>'
    ).encode()
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(0.5)
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 3702))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, addr = s.recvfrom(65535)
                if b"ProbeMatch" in data or b"onvif" in data.lower():
                    ips.add(addr[0])
            except socket.timeout:
                continue
            except OSError:
                break
        s.close()
    except OSError:
        pass
    return ips


def ssdp_discovery(wait: float = 3.0) -> dict:
    """UPnP devices answer this. Returns {ip: [description strings]}."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    found: dict = {}
    locations: dict = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(0.5)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode(errors="ignore")
            for h in ("SERVER", "ST", "USN"):
                m = re.search(rf"^{h}:\s*(.+)$", text, re.I | re.M)
                if m:
                    val = m.group(1).strip()
                    if h == "SERVER" and val not in found.setdefault(addr[0], []):
                        found[addr[0]].append(val)
            m = re.search(r"^LOCATION:\s*(\S+)", text, re.I | re.M)
            if m:
                locations.setdefault(addr[0], m.group(1))
        s.close()
    except OSError:
        pass
    # Fetch each device's description XML for its friendly name / model.
    for ip, url in locations.items():
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                xml = r.read(65536).decode(errors="ignore")
            bits = []
            for tag in ("friendlyName", "manufacturer", "modelName", "modelDescription"):
                m = re.search(rf"<{tag}>([^<]+)</{tag}>", xml)
                if m:
                    bits.append(m.group(1).strip())
            if bits:
                found.setdefault(ip, []).append(" / ".join(bits))
        except (OSError, ValueError):
            pass
    return found


def http_info(ip: str, port: int, timeout: float) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"{scheme}://{ip}:{port}/",
                                     headers={"User-Agent": "Mozilla/5.0 WifiScanner"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            server = r.headers.get("Server", "")
            body = r.read(32768).decode(errors="ignore")
    except urllib.error.HTTPError as e:  # 401 pages still tell us a lot
        server = e.headers.get("Server", "") if e.headers else ""
        realm = e.headers.get("WWW-Authenticate", "") if e.headers else ""
        try:
            body = e.read(8192).decode(errors="ignore")
        except OSError:
            body = ""
        body += " " + realm
    except (OSError, ValueError):
        return ""
    m = re.search(r"<title[^>]*>([^<]{1,120})</title>", body, re.I)
    title = m.group(1).strip() if m else ""
    hints = re.findall(r"(hikvision|dahua|webcomponents|nvr|dvr|ipcam|onvif|"
                       r"camera|reolink|amcrest|axis|foscam|xmeye|netsurveillance)",
                       body, re.I)
    parts = [p for p in (title, server) if p]
    if hints:
        parts.append("page mentions: " + ", ".join(sorted({h.lower() for h in hints})))
    return " | ".join(parts)


def rtsp_check(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
            return s.recv(256).startswith(b"RTSP/")
    except OSError:
        return False


def probe_device(dev: Device, timeout: float):
    for port in PORTS:
        if tcp_open(dev.ip, port, timeout):
            dev.open_ports.append(port)
    for port in (80, 81, 8080, 443, 8443, 5000):
        if port in dev.open_ports:
            info = http_info(dev.ip, port, timeout + 1)
            if info:
                dev.titles.append(f":{port} {info}")
    for port in (554, 8554, 10554):
        if port in dev.open_ports and rtsp_check(dev.ip, port, timeout + 1):
            dev.rtsp_ok = True
            break
    try:
        dev.hostname = socket.gethostbyaddr(dev.ip)[0]
    except OSError:
        pass


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def find_brand(text: str, table: dict) -> str:
    t = " " + text.lower() + " "
    for key in sorted(table, key=len, reverse=True):
        # whole-word-ish match so "ring" doesn't hit "spring"
        if re.search(r"(?<![a-z])" + re.escape(key) + r"(?![a-z])", t):
            return table[key]
    return ""


def score(dev: Device):
    s, why = 0, []
    if dev.is_self:
        dev.label, dev.reasons = "THIS COMPUTER", ["this is you"]
        return
    if dev.is_gateway:
        s -= 30
        why.append("your router / gateway")

    brand = find_brand(dev.vendor, CAMERA_BRANDS)
    if brand:
        s += 60
        why.append(f"made by camera brand {brand}")
        dev.brand_guess = brand
    else:
        maybe = find_brand(dev.vendor, MAYBE_CAMERA_VENDORS)
        if maybe:
            s += 15
            why.append(f"maker often builds cameras: {maybe}")
            dev.brand_guess = maybe

    text_brand = find_brand(" ".join([dev.hostname] + dev.titles + dev.upnp), CAMERA_BRANDS)
    if text_brand:
        s += 40
        why.append(f"name/web page/UPnP says '{text_brand}'")
        dev.brand_guess = dev.brand_guess or text_brand

    if dev.onvif:
        s += 60
        why.append("answered ONVIF camera discovery")
    if dev.rtsp_ok:
        s += 30
        why.append("RTSP video server responded")

    for p in dev.open_ports:
        label, pts, strong = PORTS[p]
        if pts:
            s += pts
            if pts > 0:
                why.append(f"port {p} open ({label})")
            elif pts <= -20:
                why.append(f"port {p} open ({label}) - looks like a non-camera")

    if is_random_mac(dev.mac):
        s -= 20

    dev.score = s
    dev.reasons = why
    dev.label = "CAMERA" if s >= 60 else "POSSIBLE CAMERA" if s >= 30 else "OTHER"


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

COLORS = {"CAMERA": "\033[91m", "POSSIBLE CAMERA": "\033[93m",
          "THIS COMPUTER": "\033[96m", "OTHER": ""}
RESET = "\033[0m"


def enable_ansi():
    if IS_WINDOWS:
        os.system("")  # turns on ANSI colours in Windows 10+ terminals


def print_table(devices: list, color: bool):
    print()
    hdr = f"{'IP':<16}{'MAC':<19}{'TYPE':<17}{'MAKER / NAME':<42}OPEN PORTS"
    print(hdr)
    print("-" * len(hdr) + "-" * 10)
    for d in devices:
        name = d.vendor or d.hostname or "unknown"
        if d.brand_guess and d.brand_guess.lower() not in name.lower():
            name = f"{name} [{d.brand_guess}]"
        name = name[:40]
        ports = ",".join(str(p) for p in d.open_ports) or "-"
        c = COLORS.get(d.label, "") if color else ""
        r = RESET if c else ""
        print(f"{d.ip:<16}{d.mac or '?':<19}{c}{d.label:<17}{r}{name:<42}{ports}")
        if d.label in ("CAMERA", "POSSIBLE CAMERA"):
            for why in d.reasons:
                print(f"{'':<16}  - {why}")
    print()


def write_report(devices: list, network: str, path: Path) -> Path:
    now = _dt.datetime.now().strftime("%b %d, %Y %I:%M %p")
    cams = sum(d.label == "CAMERA" for d in devices)
    maybes = sum(d.label == "POSSIBLE CAMERA" for d in devices)
    rows = []
    for d in devices:
        cls = d.label.lower().replace(" ", "-")
        ports = ", ".join(f"{p} <small>{html.escape(PORTS[p][0])}</small>" for p in d.open_ports) or "&mdash;"
        extra = "<br>".join(html.escape(x) for x in d.titles + d.upnp)
        why = "".join(f"<li>{html.escape(r)}</li>" for r in d.reasons)
        rows.append(f"""
<tr class="{cls}" data-label="{html.escape(d.label)}" data-text="{html.escape((d.ip+' '+d.mac+' '+d.vendor+' '+d.hostname+' '+extra).lower())}">
  <td><span class="pill">{html.escape(d.label)}</span><div class="score">score {d.score}</div></td>
  <td><b>{html.escape(d.ip)}</b><div class="mono">{html.escape(d.mac or '?')}</div></td>
  <td>{html.escape(d.vendor or 'Unknown maker')}<div class="muted">{html.escape(d.hostname)}</div>
      <div class="muted">{extra}</div></td>
  <td>{ports}</td>
  <td><ul>{why}</ul></td>
</tr>""")
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Scan Report</title>
<style>
:root {{ --bg:#f6f7f9; --card:#fff; --ink:#15181d; --muted:#6a717d; --line:#e3e6ea;
        --cam:#d92d20; --cam-bg:#fdecea; --maybe:#b54708; --maybe-bg:#fef4e6;
        --me:#0b6bcb; --me-bg:#e8f1fb; }}
@media (prefers-color-scheme: dark) {{
 :root {{ --bg:#101216; --card:#181b21; --ink:#e9ecf1; --muted:#9aa2ae; --line:#2a2f37;
         --cam:#ff6b5e; --cam-bg:#3a1714; --maybe:#ffb454; --maybe-bg:#382810;
         --me:#5aa9ff; --me-bg:#132739; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--ink);
       font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
main {{ max-width:1200px; margin:0 auto; padding:24px 16px 48px }}
h1 {{ margin:0 0 4px; font-size:24px }}
.muted {{ color:var(--muted); font-size:13px }}
.stats {{ display:flex; gap:12px; flex-wrap:wrap; margin:18px 0 }}
.stat {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
        padding:12px 16px; min-width:130px }}
.stat b {{ display:block; font-size:26px }}
.stat.cam b {{ color:var(--cam) }} .stat.maybe b {{ color:var(--maybe) }}
.bar {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px }}
.bar input {{ flex:1; min-width:200px; padding:10px 12px; border-radius:10px;
             border:1px solid var(--line); background:var(--card); color:var(--ink); font:inherit }}
.bar button {{ padding:10px 14px; border-radius:10px; border:1px solid var(--line);
              background:var(--card); color:var(--ink); font:inherit; cursor:pointer }}
.bar button.on {{ border-color:var(--ink) }}
.wrap {{ overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:12px }}
table {{ border-collapse:collapse; width:100%; min-width:820px }}
th, td {{ text-align:left; vertical-align:top; padding:10px 12px; border-bottom:1px solid var(--line) }}
th {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted) }}
td ul {{ margin:0; padding-left:18px }} td small {{ color:var(--muted) }}
.mono {{ font-family:ui-monospace,Consolas,monospace; font-size:12px; color:var(--muted) }}
.pill {{ display:inline-block; padding:2px 8px; border-radius:99px; font-size:12px;
        font-weight:600; background:var(--line) }}
.score {{ font-size:11px; color:var(--muted); margin-top:4px }}
tr.camera {{ background:var(--cam-bg) }} tr.camera .pill {{ background:var(--cam); color:#fff }}
tr.possible-camera {{ background:var(--maybe-bg) }} tr.possible-camera .pill {{ background:var(--maybe); color:#fff }}
tr.this-computer .pill {{ background:var(--me); color:#fff }}
.note {{ margin-top:18px; font-size:13px; color:var(--muted) }}
</style></head><body><main>
<h1>WiFi Scan Report</h1>
<div class="muted">Network {html.escape(network)} &middot; {now} &middot; WifiScanner {VERSION}</div>
<div class="stats">
  <div class="stat"><b>{len(devices)}</b>devices found</div>
  <div class="stat cam"><b>{cams}</b>likely cameras</div>
  <div class="stat maybe"><b>{maybes}</b>possible cameras</div>
</div>
<div class="bar">
  <input id="q" placeholder="Search IP, MAC, maker, name...">
  <button data-f="all" class="on">All</button>
  <button data-f="cam">Cameras only</button>
</div>
<div class="wrap"><table>
<thead><tr><th>Type</th><th>Address</th><th>Maker / name</th><th>Open ports</th><th>Why</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<p class="note">Scores are a best guess from the device maker, discovery replies and open ports.
Cameras that only talk to the cloud (some Ring, Blink, Wyze, Nest) may show as "possible" or "other" -
look at the maker column. Devices that were asleep during the scan may be missing; run it again.
Private/random MACs are usually phones or laptops.</p>
</main>
<script>
const q=document.getElementById('q'); let f='all';
function apply(){{ const s=q.value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(r=>{{
    const camOk = f==='all' || /CAMERA/.test(r.dataset.label) && r.dataset.label!=='THIS COMPUTER';
    r.style.display = camOk && r.dataset.text.includes(s) ? '' : 'none'; }}); }}
q.addEventListener('input',apply);
document.querySelectorAll('.bar button').forEach(b=>b.onclick=()=>{{
  document.querySelectorAll('.bar button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on'); f=b.dataset.f; apply(); }});
</script></body></html>"""
    path.write_text(page, encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def guess_network(ip: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def scan(args) -> list:
    q = args.quiet
    me = local_ip()
    if me.startswith("127."):
        sys.exit("Couldn't find your network address. Are you connected to WiFi?")
    net = ipaddress.ip_network(args.network, strict=False) if args.network else guess_network(me)
    if net.num_addresses > 4096:
        sys.exit("That network is very large; use something like /24 (256 addresses).")
    gw = default_gateway()
    log(f"\nWifiScanner {VERSION}")
    log(f"  Your IP: {me}   Router: {gw or 'unknown'}   Scanning: {net} "
        f"({net.num_addresses - 2} addresses)\n", q)

    oui = load_oui(args.refresh_vendors, q)

    log("  [1/4] Looking for camera discovery replies (ONVIF + UPnP)...", q)
    with cf.ThreadPoolExecutor(2) as ex:
        f_onvif = ex.submit(ws_discovery, 3.0)
        f_ssdp = ex.submit(ssdp_discovery, 3.0)
        onvif_ips, ssdp = f_onvif.result(), f_ssdp.result()

    log("  [2/4] Sweeping the network for devices...", q)
    hosts = [str(h) for h in net.hosts()]
    alive = set()
    with cf.ThreadPoolExecutor(args.threads) as ex:
        futs = {ex.submit(wake, h, args.timeout_ms): h for h in hosts}
        done = 0
        for fut in cf.as_completed(futs):
            done += 1
            if fut.result():
                alive.add(futs[fut])
            if not q and done % 32 == 0:
                print(f"\r        {done}/{len(hosts)} checked, {len(alive)} answering", end="", flush=True)
    log(f"\r        {len(hosts)}/{len(hosts)} checked, {len(alive)} answering   ", q)

    arp = read_arp()
    in_net = {ip: mac for ip, mac in arp.items()
              if ipaddress.ip_address(ip) in net}
    ips = alive | set(in_net) | {ip for ip in onvif_ips | set(ssdp)
                                 if ipaddress.ip_address(ip) in net}
    ips.add(me)

    devices = {}
    for ip in ips:
        d = Device(ip=ip, mac=in_net.get(ip, ""))
        if ip == me:
            d.is_self, d.mac = True, d.mac or own_mac()
        d.is_gateway = ip == gw
        d.vendor = vendor_for(d.mac, oui)
        d.onvif = ip in onvif_ips
        d.upnp = ssdp.get(ip, [])
        devices[ip] = d

    log(f"  [3/4] Checking {len(devices)} devices for camera ports and web pages...", q)
    timeout = args.timeout_ms / 1000
    with cf.ThreadPoolExecutor(min(32, len(devices))) as ex:
        list(ex.map(lambda d: probe_device(d, timeout),
                    [d for d in devices.values() if not d.is_self]))

    log("  [4/4] Scoring...", q)
    for d in devices.values():
        score(d)
    return sorted(devices.values(), key=lambda d: d.sort_key), str(net)


def main():
    ap = argparse.ArgumentParser(description="Find devices on your WiFi and flag likely cameras.")
    ap.add_argument("--network", help="network to scan, e.g. 192.168.1.0/24 (default: auto)")
    ap.add_argument("--cameras", action="store_true", help="only list likely/possible cameras")
    ap.add_argument("--find", action="append", default=[], metavar="WORD",
                    help="only list devices whose maker/name/page mentions WORD (repeatable)")
    ap.add_argument("--threads", type=int, default=128, help="parallel checks (default 128)")
    ap.add_argument("--timeout-ms", type=int, default=600, help="per-check timeout (default 600)")
    ap.add_argument("--no-report", action="store_true", help="don't write the HTML report")
    ap.add_argument("--no-open", action="store_true", help="don't open the report in a browser")
    ap.add_argument("--json", metavar="FILE", help="also save results as JSON")
    ap.add_argument("--refresh-vendors", action="store_true", help="re-download the MAC vendor list")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="less progress output")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()

    enable_ansi()
    t0 = time.time()
    devices, network = scan(args)

    shown = devices
    if args.cameras:
        shown = [d for d in shown if d.label in ("CAMERA", "POSSIBLE CAMERA")]
    if args.find:
        words = [w.lower() for w in args.find]
        shown = [d for d in shown if any(
            w in " ".join([d.vendor, d.hostname, d.brand_guess, d.mac, d.ip]
                          + d.titles + d.upnp).lower() for w in words)]

    print_table(shown, color=not args.no_color and sys.stdout.isatty())
    cams = [d for d in devices if d.label == "CAMERA"]
    maybes = [d for d in devices if d.label == "POSSIBLE CAMERA"]
    print(f"Found {len(devices)} devices in {time.time() - t0:.0f}s: "
          f"{len(cams)} likely camera(s), {len(maybes)} possible.")

    if args.json:
        Path(args.json).write_text(json.dumps([asdict(d) for d in devices], indent=2))
        print(f"JSON saved to {args.json}")
    if not args.no_report:
        name = f"wifi_report_{_dt.datetime.now():%Y%m%d_%H%M%S}.html"
        path = write_report(shown, network, Path.cwd() / name)
        print(f"Report saved to {path}")
        if not args.no_open:
            try:
                webbrowser.open(path.as_uri())
            except Exception:
                pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
