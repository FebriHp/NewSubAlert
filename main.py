import requests
import json
import time
import os
from datetime import datetime
from bs4 import BeautifulSoup

# ============== CONFIGURATION ==============
TELEGRAM_BOT_TOKEN = "TOKEN"
TELEGRAM_CHAT_ID = "CHAT_ID"
SHODAN_API_KEY = "SHODAN_API"
VULNERS_API_KEY = "VULNERS_API"

DOMAIN_LIST = ["a.com", "b.com"]
MAX_AGE_DAYS = 180
CHECKED_FILE = "checked.json"
SLEEP_INTERVAL = 3600
DOWNLOAD_FOLDER = "downloaded"
# ===========================================

def send_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, data=data, timeout=10)
    except Exception as e:
        print(f"[ERROR] Telegram text: {e}")

def send_telegram_file(filepath, caption=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    try:
        with open(filepath, 'rb') as file:
            files = {'document': file}
            data = {'chat_id': TELEGRAM_CHAT_ID}
            if caption:
                data['caption'] = caption
            requests.post(url, files=files, data=data, timeout=20)
    except Exception as e:
        print(f"[ERROR] Telegram file: {e}")

def load_checked():
    if not os.path.exists(CHECKED_FILE):
        return {}
    with open(CHECKED_FILE, "r") as f:
        return json.load(f)

def save_checked(data):
    with open(CHECKED_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return list({entry['name_value'] for entry in data if domain in entry['name_value']})
    except Exception as e:
        print(f"[ERROR] Fetching subdomains for {domain}: {e}")
    return []

def is_recent(subdomain):
    url = f"https://crt.sh/?q={subdomain}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                if entry['name_value'] == subdomain:
                    not_before = entry['not_before']
                    created = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%S")
                    age_days = (datetime.utcnow() - created).days
                    return age_days <= MAX_AGE_DAYS, created.date()
    except Exception as e:
        print(f"[ERROR] Checking age for {subdomain}: {e}")
    return False, None

def check_http(subdomain):
    url = f"http://{subdomain}"
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No Title"
        return r.status_code, title
    except:
        return None, "Unreachable"

def resolve_ip(subdomain):
    try:
        result = requests.get(f"https://dns.google/resolve?name={subdomain}&type=A", timeout=5).json()
        if "Answer" in result:
            return result["Answer"][0]["data"]
    except:
        pass
    return None

def get_cve_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('vulns', [])
    except Exception as e:
        print(f"[ERROR] Shodan CVE: {e}")
    return []

def get_cve_vulners(domain):
    try:
        url = "https://vulners.com/api/v3/search/lucene/"
        params = {"query": domain, "apiKey": VULNERS_API_KEY}
        resp = requests.post(url, json=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return [x['id'] for x in data.get('data', {}).get('search', []) if x['type'] == 'cve']
    except Exception as e:
        print(f"[ERROR] Vulners CVE: {e}")
    return []

def format_cve_list(shodan_cves, vulners_cves):
    combined = {}
    for cve in shodan_cves:
        combined[cve] = combined.get(cve, []) + ['Shodan']
    for cve in vulners_cves:
        combined[cve] = combined.get(cve, []) + ['Vulners']

    result = ""
    for cve, sources in combined.items():
        result += f"- `{cve}` ({', '.join(set(sources))})\n"
    return result.strip()

def scan_sensitive_files(subdomain):
    paths = [".env", "config.php", ".git/config", "backup.zip", "database.sql"]
    findings = []
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

    for path in paths:
        url = f"http://{subdomain}/{path}"
        try:
            resp = requests.get(url, timeout=6, allow_redirects=True)
            content_type = resp.headers.get("Content-Type", "").lower()

            if resp.status_code == 200 and "html" not in content_type:
                if "json" in content_type:
                    findings.append(f"- `{path}` → 200 OK (JSON): {url}")
                elif "xml" in content_type:
                    findings.append(f"- `{path}` → 200 OK (XML): {url}")
                else:
                    filename = f"{subdomain.replace('.', '_')}_{path.replace('/', '_')}"
                    fullpath = os.path.join(DOWNLOAD_FOLDER, filename)
                    with open(fullpath, "wb") as f:
                        f.write(resp.content)
                    send_telegram_file(fullpath, caption=f"{subdomain} → {path}")
                    os.remove(fullpath)
                    findings.append(f"- `{path}` → 200 OK (file sent)")
        except:
            continue
    return findings

def run():
    checked = load_checked()
    while True:
        for domain in DOMAIN_LIST:
            if domain not in checked:
                checked[domain] = []

            print(f"[INFO] Checking domain: {domain}")
            subdomains = get_subdomains(domain)

            for sub in subdomains:
                if sub in checked[domain]:
                    continue

                recent, tgl = is_recent(sub)
                if recent:
                    status, title = check_http(sub)
                    ip = resolve_ip(sub)
                    shodan_cves = get_cve_shodan(ip) if ip else []
                    vulners_cves = get_cve_vulners(sub)
                    cve_result = format_cve_list(shodan_cves, vulners_cves)

                    files_found = scan_sensitive_files(sub)
                    file_section = "\n📂 *Sensitive Files:*\n" + "\n".join(files_found) if files_found else ""

                    message = (
                        f"🔔 *{domain} - New subdomain detected!*\n"
                        f"`{sub}`\n📅 First Seen: {tgl}\n"
                        f"📄 Status: `{status}`\n📝 Title: *{title}*\n"
                        f"\n*CVEs:*\n{cve_result if cve_result else 'None found'}"
                        f"{file_section}"
                    )
                    print(message)
                    send_telegram(message)

                checked[domain].append(sub)

            save_checked(checked)
            print(f"[INFO] Domain {domain} done. Waiting 1 minute...\n")
            time.sleep(60)

        print(f"[INFO] All domains checked. Sleeping for {SLEEP_INTERVAL // 60} minutes...\n")
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    run()
