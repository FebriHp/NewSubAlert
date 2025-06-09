# Subdomain Monitoring and Vulnerability Alert Bot

This script monitors a list of domains for newly discovered subdomains via `crt.sh`. For each new subdomain found, it checks its availability, resolves the IP, detects known CVEs using Shodan and Vulners APIs, and attempts to access sensitive files. All findings are reported via Telegram bot.

---

## 🛠 Features

- Discover new subdomains using `crt.sh`
- Check if subdomains are recently created
- Fetch web title and HTTP status
- Resolve IP address
- Fetch CVE vulnerabilities using:
  - [Shodan API](https://www.shodan.io/)
  - [Vulners API](https://vulners.com/)
- Attempt to detect and send sensitive files:
  - `.env`, `.git/config`, `config.php`, `backup.zip`, `database.sql`
- Notify all results via Telegram

---

## 🚀 How to Use

### 1. Clone Repository
```bash
git clone https://github.com/FebriHp/NewSubAlert.git
cd NewSubAlert
```

### 2. Prepare Environment Variables
Edit the script or use a `.env` management system:
```python
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"
SHODAN_API_KEY = "YOUR_SHODAN_KEY"
VULNERS_API_KEY = "YOUR_VULNERS_KEY"
DOMAIN_LIST = ["example.com", "test.com"]
```

### 3. Run with Docker
#### Build
```bash
docker build -t submonitor .
```
#### Run
```bash
docker run --rm submonitor
```

---

## 📝 Notes

⚠️ **This script is still under development and testing phase. Use responsibly.**

Suggestions, contributions, and improvements are welcome!
