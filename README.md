![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Built with Python](https://img.shields.io/badge/Made_with-Python-blue?logo=python)
![Terminal Only](https://img.shields.io/badge/UI-Terminal-orange)
![Cross-Platform](https://img.shields.io/badge/Platform-macOS_|_Linux_|_Windows-purple)
# 🧠 NetHtop++ (alpha)

> **Network Hunt Console with Ghost Response Playbooks**  
> _The NETWORK ARMY KNIFE you wish you had 10 years ago._
                                                                                                                                                                                  
 <img width="1488" height="1365" alt="Screenshot 2025-09-24 at 8 13 47 PM" src="https://github.com/user-attachments/assets/a54faa25-1f53-46e1-af34-4a202d0e9b51" />
 <img width="1492" height="1366" alt="Screenshot 2025-09-24 at 8 14 40 PM" src="https://github.com/user-attachments/assets/aed5270d-1e22-45e0-8b93-7e06a583a9a9" />
                                                                                                                
  *Those screenshots are from an APT infected macOS system. Since it is a Mac mini there are a lot of interfaces but NetHtop++ only lists the interface running on your system. Not all possible interfaces. 60 ghost sockets is not normal macOS behaviour, nor any normal system*                                                                                                                                                                            
                                                                                                                                                                                                                            
 ## 🧰 What is NetHtop++?

NetHtop++ is a real-time **network inspection and response console** built for operators, analysts, hackers, blue teamers, red teamers, and *those who need to know what the hell is going on* — fast.

Inspired by `htop`, but for sockets and flows, NetHtop++ fuses multiple tools into a single, powerful, terminal-native battlefield command interface. Run with sudo since... Well it is interactive and can do many things that require priviledges. IE: killing sockets, adding pf rules, killswitch feature from the ghost sockets interface but be careful using the playbook in the ghost sockets overlay because it combines powerful features that could break your networking. Always backup you pf.conf before adding the whole ghost sockets list to pf. I'll add other firewalls support soon or tweak the script to include the firewall you use. 

🧠 It's **htop for networks.**  
👻 It's **a ghost hunter.**  
💣 It's **a one-key SIEM.**  
⚔️ It's **the Swiss Army Knife of NetOps.**

---

## 🧨 Features

| Feature | Description |
|--------|-------------|
| 🔍 **Live Socket Inspector** | Real-time view of all TCP/UDP connections, resolved hostnames, states, PIDs, and more. |
| 💀 **Ghost Socket Detection** | Reveal and count stealthy sockets not exposed via typical tools, scored by confidence. |
| 🎯 **One-Key Tracing** | Press `z` to trace route of selected connection. |
| 📡 **Targeted Tcpdump** | Press `t` to launch a targeted `tcpdump` on the selected connection's interface. |
| 🧾 **PCAP Logging** | Captures are auto-saved in `nethtop` directory. |
| 📈 **Interface Throughput Graphs** | TX/RX bars per interface. Always visible. Real-time updates. |
| 🔪 **Process Killing** | Kill offending connections instantly with `p`. |
| 🧠 **Playbooks + Countermeasures** | Ghost socket recon tools and embedded response flow. |
| 🌐 **Resolve Mode** | Instantly resolve IPs to hostnames (`r`). |
| 💾 **Export to Log** | Full session dump to log file. |
| 🖥️ **Terminal-aware Layout** | ASCII banner enforces optimal terminal width and mental clarity. |

---

## 🧠 Philosophy

> _“This is not a tool you run. This is a **console you deploy.**”_

From the moment you launch, NetHtop++ sets the stage:
- ASCII banner primes your **operator mindset**.
- Terminal resizes itself to fit tactical layout.
- Keys behave like live toggles. No menus. No clutter.

You're not watching the network.  
You're **interrogating** it.

Stop duct-taping five tools together. Here’s your damn console.
---

## 🔧 Requirements

- Python 3.8+
- `psutil>=5.9`
- `ipwhois>=1.2` (optional, for IP enrichment)

### Platform-specific notes

| Platform | Extra dependency | Notes |
|----------|-----------------|-------|
| **macOS** 🍎 | None | Full features: tcpdump capture, pfctl firewall blocks, launchd scanning |
| **Linux** 🐧 | None | Full features: tcpdump capture, /proc socket control |
| **Windows** 🪟 | `windows-curses>=2.3` | tcpdump/pfctl/launchd gracefully disabled; use `Kill Process` for socket control |

> *Same file, all platforms — `nethtop++.py` auto-detects your OS and adapts.*

---

## 🛡️ Read-only by default

NetHtop++ opens in **read-only mode**: `p` (kill), `x` (close socket), and the
ghost playbook (`K` graceful kill, `F` firewall block, `R` restart daemons,
`H` hard kill) all require a **y/N confirmation** before acting. The header
shows `[READ-ONLY]` while this is active.

```bash
sudo python3 nethtop++.py --response   # response mode: destructive keys act immediately
```

Response mode displays `[RESPONSE]` in the header. Use it deliberately — it
skips every confirmation.

### Privilege separation

- Run the console **unprivileged** for monitoring. It works fine without root.
- Privileged operations (`pfctl` blocks, killing other users' processes,
  `/proc` socket access) only succeed when you run elevated — use
  `sudo python3 nethtop++.py` (optionally with `--response`) only for actual
  response work.
- Ghost detection accounts for the privilege gap: an unprivileged `lsof`
  cannot attribute other users' sockets, so those inventory differences are
  reported at **lower confidence** with a note, and the alert carries a hint
  to re-scan elevated for full-strength attribution.

### Ghost sockets are a confidence score, not a binary verdict

Kernel (`netstat -anv` on macOS, `/proc/net/{tcp,tcp6,udp,udp6}` on Linux)
and userland (`lsof`) inventories are compared on canonical `host:port` keys.
Each mismatch is scored **0.0–1.0** with its reasons:

| Signal | Effect |
|--------|--------|
| Owned by a live process (psutil) | −0.40 — likely a tool race |
| Unprivileged scan | −0.35 — may be another user's socket |
| Unowned `LISTEN` socket | +0.15 |
| Active `ESTABLISHED` session | +0.05 |
| Persistent across scans | +0.10 per scan (max +0.30) |

Entries at/above **0.70** raise a warning; the overlay sorts by confidence.
When `lsof` or `netstat` is missing (or `lsof` returns nothing), detection
reports **"ghost detection unavailable"** — it never treats an empty
inventory as "no ghosts".

### Optional tools

Detected at startup and reported in the status line:

| Tool | Feature |
|------|---------|
| `lsof` | Ghost detection (userland inventory) |
| `netstat` | Ghost detection (kernel inventory, macOS/BSD) |
| `tcpdump` | Packet capture |
| `traceroute` / `tracepath` | Route tracing |

Missing tools disable their feature gracefully — no crashes, no fake data.

### Tests

Parser fixtures + unit tests live in `tests/` (stdlib `unittest`, zero extra
dependencies) and cover macOS `netstat -anv`, Linux `/proc/net`, and `lsof -F`
output:

```bash
python3 -m unittest discover -s tests -v
```

---

## 🚀 Installation

### macOS / Linux
```bash
git clone https://github.com/m10ust/nethtop.git
cd nethtop
pip install -r requirements.txt
sudo python3 nethtop++.py
```

### Windows
```powershell
git clone https://github.com/m10ust/nethtop.git
cd nethtop
pip install -r requirements.txt
python nethtop++.py
```

> *Windows doesn’t need `sudo` — just run it. Packet capture (tcpdump) and firewall blocks (pfctl) show a helpful message instead of crashing.*

---
