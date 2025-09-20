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
```

🚦 How to Contribute
	1.	Fork the repo
	2.	Create a branch:
git checkout -b my-feature-name
	3.	Hack. Test. Iterate.
	4.	Open a Pull Request
	5.	Explain what, why, and how in the PR description.

⸻

🚨 Pull Request Checklist
	•	Code runs on both macOS and Linux
	•	Doesn’t break existing flow (unless it’s an upgrade)
	•	Feature has a toggle key if it’s interactive
	•	You tested it live
	•	You added yourself to the CONTRIBUTORS.md if you added >10 lines

⸻

🧬 Ground Truth

This is not a toy. This is not a pretty dashboard.
NetHtop++ is for people who get paged at 3am and need answers.
Make it better for them — or leave it alone.
