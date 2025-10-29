![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Built with Python](https://img.shields.io/badge/Made_with-Python-blue?logo=python)
![Terminal Only](https://img.shields.io/badge/UI-Terminal-orange)
# 🧠 NetHtop++ (alpha)

> **Network Hunt Console with Ghost Response Playbooks**  
> _The NETWORK ARMY KNIFE you wish you had 10 years ago._
                                                                                                                                                                                  
 <img width="1488" height="1365" alt="Screenshot 2025-09-24 at 8 13 47 PM" src="https://github.com/user-attachments/assets/a54faa25-1f53-46e1-af34-4a202d0e9b51" />
 <img width="1492" height="1366" alt="Screenshot 2025-09-24 at 8 14 40 PM" src="https://github.com/user-attachments/assets/aed5270d-1e22-45e0-8b93-7e06a583a9a9" />
                                                                                                                
  **Those screenshots are from an APT infected macOS system. Since it is a Mac mini there are a lot of interfaces but NetHtop++ only lists the interface running on your system. Not all possible interfaces. 60 ghost sockets is not normal macOS behaviour, nor any normal system**                                                                                                                                                                            
                                                                                                                                                                                                                            
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
| 💀 **Ghost Socket Detection** | Reveal and count stealthy sockets not exposed via typical tools. |
| 🎯 **One-Key Tracing** | Press `t` to trace route of selected connection. |
| 📡 **Targeted Tcpdump** | Press `c` to launch a targeted `tcpdump` on the selected connection's interface. |
| 🧾 **PCAP Logging** | Captures are auto-saved in `nethtop` directory. |
| 📈 **Interface Throughput Graphs** | TX/RX bars per interface. Always visible. Real-time updates. |
| 🔪 **Process Killing** | Kill offending connections instantly with `k`. |
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

- Python 3.7+
psutil>=5.9
ipwhois>=1.2

> *Works best on macOS or Linux terminal with minimum 110 character width.*

---

## 🚀 Installation

```bash
git clone https://github.com/m10ust/nethtop.git
cd nethtop
pip install -r requirements.txt
sudo python3 nethtop++.py
```

If you’re not happy with it, open a fucking issue or make a pull request with the fix. You are welcome to make a Windows version fork if you want because I am not gonna do it. 
