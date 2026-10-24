# WifiScanner

Finds every device on your WiFi and flags the ones that are likely **cameras** (IP cams, NVR/DVRs, doorbells). Handy for checking a rental or hotel room for hidden cameras, or just seeing what's on your own network.

Only scan networks you own or have permission to scan.

## Run it (Windows)

1. Install Python 3 from https://www.python.org/downloads/ — tick **"Add python.exe to PATH"**.
2. Download this repo (green **Code** button → **Download ZIP**) and unzip it.
3. Double-click **`run_scan.bat`**.

A report opens in your browser when it's done (about 30–60 seconds). Red rows are likely cameras, orange are possible.

Linux/Android (Termux): `python3 wifiscanner.py`

## Options

```
python wifiscanner.py --cameras              # only show likely/possible cameras
python wifiscanner.py --find ring --find wyze  # look for certain devices by name/maker
python wifiscanner.py --network 192.168.0.0/24
python wifiscanner.py --json results.json    # save raw results
python wifiscanner.py --no-open              # don't pop open the browser
```

## How it decides something is a camera

| Signal | Why it matters |
|---|---|
| MAC maker (Hikvision, Dahua, Reolink, Wyze, Amcrest, Foscam…) | Strongest clue — looked up from the IEEE vendor list (downloaded once, cached) |
| Answers ONVIF discovery | Almost only cameras/NVRs do this |
| RTSP port 554 / 8554 responds | Video streaming server |
| Ports 37777 (Dahua), 34567 (XMeye), 8000 (Hikvision), 2020 (Tapo) | Camera-specific services |
| Web page title / UPnP name | e.g. "NVR", "IPCamera", "Hikvision" |
| iPhone sync, Windows sharing, printer ports | Lowers the score (not a camera) |

## Limits

- Cloud-only cameras (some Ring, Blink, Nest, Wyze) open no local ports, so they may only show as "possible" based on maker. Check the maker column.
- Devices on a guest network or a different WiFi band that's isolated won't be visible.
- Sleeping battery cameras may not answer — run it a couple of times.
- "Private/random MAC" devices are almost always phones or laptops.
