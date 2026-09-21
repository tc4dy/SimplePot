![Logo](sp.svg)

# SimplePot – See How Attackers Think & Defend

>  *An MVP (Minimum Viable Product) honeypot consisting of approximately 2,500 lines of code—suitable for IT companies, researchers, and developers—featuring a fully functional design that is open to further development and adaptable for production environments. **(For ease of use, the modular components have been consolidated into a single file for developers.)** This single-file version integrates AI support while retaining identical functionality. *

**350‑char description:**  
🔍 Observe live SSH brute‑force, SQLi, DNS tunnelling & more.  
📡 12+ protocols (HTTP/SSH/FTP/Redis/DNS/SNMP/Modbus/WebSocket).  
📊 SQLite + live dashboard + MITRE ATT&CK mapping.  
🛠️ Clone, run, learn, extend. **Not a commercial product – a learning toolkit.**  

 **Clone:** `git clone https://github.com/tc4dy/SimplePot`  

---

## [?] What is this?

**SimplePot** is a low‑interaction honeypot written from scratch in Python asyncio.  
It simulates common network services, logs every attacker action, and maps events to MITRE ATT&CK techniques.

**This is not a polished enterprise tool.**  
It was built by **one person** to understand attack patterns, test detection logic, and provide a **transparent, hackable** base for learning.  
The code is ~2500 lines, monolithic by design – so you can read, modify, and improve it without hunting through dozens of files.

---

## [+] MVP and Educational Goals

- See **exactly what credentials** attackers try (SSH, FTP, MySQL, SMTP, HTTP forms).
- Watch **live commands** on a fake shell (`id`, `wget`, `cat /etc/passwd`).
- Learn how **threat scoring** works (payload patterns + behaviour).
- Understand **MITRE ATT&CK mapping** (25+ techniques directly from flags).
- Experiment with **active defence** (rate limiting, iptables banning).
- Build your own **fake responses** by editing Python dicts.

---

## Capabilities

SimplePot focuses on **detection, learning, and transparency**. Here's what
runs out-of-the-box today:

**Protocols (11 total)**
- SSH · HTTP · HTTPS · FTP · MySQL · SMTP · Redis · Modbus · DNS (TCP + UDP) · SNMP · WebSocket

**Detection & intelligence**
- Payload pattern matching (SQLi, XSS, LFI, RCE, WebShell, cryptomining, botnet, DNS tunnelling)
- Threat scoring (0–100) combining behaviour, frequency, and known-bad indicators
- MITRE ATT&CK mapping — 25+ techniques across 8 tactics
- Per-IP attacker profiling (credentials, commands, protocols, techniques)

**Operations**
- Live web dashboard with real-time stats
- Prometheus metrics endpoint (`/metrics`)
- Slack, Telegram, and generic webhook alerting
- SQLite persistence (WAL mode, batched writes)
- GDPR-friendly IP anonymisation in logs and exports
- STIX 2.1 export for threat-intel sharing

**Defence**
- Rate limiting per IP
- Automatic `iptables` banning above threat threshold
- Configurable session timeouts and tarpitting

> Designed for **moderate traffic** (hundreds of events/minute) on a single
> node — enough for a home lab, a research VM, or a small office network.
> For massive-scale production, pair it with T-Pot or Cowrie.

---

##  How it works (the logic, step by step)

1. **Service emulation** – each protocol runs in an `asyncio` server.
2. **Connection** – logs source IP, creates a session, checks rate‑limits / bans.
3. **Interaction** – depending on the protocol:
   - SSH: fake shell with hardcoded command responses (`SSH_COMMANDS` dict).
   - HTTP: fake admin panels, login forms, API endpoints, `.env` files.
   - FTP/MySQL/SMTP/Redis: minimal banner + credential capture.
   - DNS: logs queries, flags long subdomains as tunnelling.
   - Modbus: responds with error code, raises ICS alert.
4. **Payload analysis** – regex patterns against raw data → flags (SQLi, XSS, RCE, …).
5. **Threat score** – combines flags, event frequency, known bad IPs, protocol diversity.
6. **MITRE mapping** – converts flags + event type into ATT&CK technique IDs (T1110, T1190, …).
7. **Persistence** – events are batch‑written to SQLite (WAL mode) to avoid locking.
8. **Alerting** – if score ≥ threshold (70), sends to Slack/Telegram/webhook (cooldown per IP).
9. **Dashboard** – live stats, top attackers, MITRE tags, export JSON/STIX.

All fake banners, files, SSH command responses are plain Python data structures – you can change them without restarting (except config).

---

## [%] Installation & first run

```bash
git clone https://github.com/tc4dy/SimplePot
cd SimplePot
pip install aiohttp asyncssh dnspython cryptography
sudo python3 simplepot.py   # sudo needed only for iptables banning
```
Ports used (change in CONFIG dict):
2222 (SSH), 8080 (HTTP), 8443 (HTTPS), 2121 (FTP), 3306 (MySQL), 2525 (SMTP), 6379 (Redis), 502 (Modbus), 5353 (DNS), 1610 (SNMP).
Dashboard: http://localhost:7777
Prometheus metrics: http://localhost:7777/metrics

🧪 Try it yourself

```bash
# SSH brute‑force simulation
ssh -p 2222 root@localhost          # any password works for root

# HTTP credential stuffing
curl -X POST http://localhost:8080/wp-login.php -d "log=admin&pwd=12345"

# DNS tunnelling detection
dig @localhost -p 5353 a.very.long.subdomain.that.looks.suspicious.example.com

# Modbus ICS scan
nmap -p 502 --script modbus-discover localhost
```

Open the dashboard – every event appears with a threat score and MITRE tags.
Project structure (single file – easy to explore)
text

simplepot.py           # all classes and logic (~2500 lines)
/tmp/honeypot_data/    # runtime data
  ├── honeypot.db      # SQLite database
  ├── keys/            # SSH host key
  └── certs/           # self‑signed TLS cert for HTTPS

Because everything is in one file, you can search, modify, and run without context‑switching – ideal for learning.
Environment variables for alerts

```bash
export SLACK_WEBHOOK="https://hooks.slack.com/..."
export TELEGRAM_TOKEN="123456:ABC"
export TELEGRAM_CHAT_ID="-123456"
export WEBHOOK_URL="https://your-endpoint.com/alert"
```

## Roadmap

SimplePot is an MVP. The roadmap below reflects **what I plan to add**, in
rough priority order. No dates — this is a side project.

### Short term
- [ ] `config.yaml` support (no more editing the Python file)
- [ ] Dashboard basic auth (single user, token-based)
- [ ] Dockerfile + `docker-compose.yml`
- [ ] Persistent log path via environment variable
- [ ] JSON structured logging option

### Mid term
- [ ] Unit tests with `pytest` (DB, scoring, MITRE mapping)
- [ ] Per-endpoint alert tuning (Slack / Telegram / webhook)
- [ ] GeoIP enrichment (optional, offline database)
- [ ] Tor exit-node detection (bulk list)
- [ ] Prometheus exporter improvements (histograms, per-protocol counters)

### Long term (maybe)
- [ ] Plugin system for custom honeypot services
- [ ] Helm chart
- [ ] Full IPv6 support
- [ ] Postgres backend (optional, for multi-node)
- [ ] Malware payload capture with safe storage

## License

MIT License — see [`LICENSE`](LICENSE) for the full text :p
