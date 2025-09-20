# 🤝 Contributing to NetHtop++

**Welcome, warrior.**  
NetHtop++ isn’t just a script — it’s a tactical console.  
If you’re here, you’re either trying to make it better, break it smarter, or bend it to your own twisted brilliance. All of that is welcome.

---

## ⚔️ Rules of Engagement

### 🛠 What You Can Do
- **Fix bugs** — found a broken keybind, a missed edge case? Patch it.
- **Add features** — but make sure they align with the “single-screen, zero-menu, operator-mode” mindset.
- **Improve docs** — more clarity, more users, less confusion.
- **Open issues** — even just observations. If something *feels* off, it probably is.
- **Submit PRs** — whether it's one-line patch or a full subsystem, bring it.

---

## 🧠 Design Philosophy

- **Live-first.** If it requires multiple menus, it’s dead to us.
- **Minimal deps.** Heavy-lift, but lightweight.
- **Readability over cleverness.** Your code should be explainable during a caffeine crash.
- **Field-usable.** It should *run* on macOS and Linux terminals. No GUI. No fluff.

---

## 🧰 Dev Environment

### Requirements
- Python 3.7+
- `psutil`, `scapy`, `netifaces`, `colorama`
- Linux/macOS terminal
- Minimum terminal width: **110 characters**

Install:
```bash
git clone https://github.com/m10ust/nethtop.git
cd nethtop
pip install -r requirements.txt
sudo python3 nethtop++.py
