import requests
import json
import time
import os
from datetime import datetime
from bs4 import BeautifulSoup

# ============== KONFIGURASI ==============
TELEGRAM_BOT_TOKEN = "7561676850:AAFaIR88IcLFX7in_6QVhAGSP_QoLYQ0ZOI"
TELEGRAM_CHAT_ID = "6690951901"
MAX_AGE_DAYS = 180
DOMAIN_LIST = ["nasa.gov", "dell.com", "intel.com", "oppo.com"]  # Tambahkan domain lain di sini
CHECKED_FILE = "checked.json"
SLEEP_INTERVAL = 3600  # Waktu jeda antar siklus penuh (dalam detik)

SHODAN_API_KEY = "BOdGuR5XJu4ny9SM3qkltjPukUvP3ILY"
VULNERS_API_KEY = "UJ726PQ7LXLRDKCZ0NVKDPYJ5SGAWBRZ1MRSXO9FI6E4HL4CTEZPDN1WI7KS8BE5"
# =========================================

def send_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, data=data, timeout=10)
    except Exception as e:
        print(f"[ERROR] Gagal kirim notifikasi: {e}")

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
        print(f"[ERROR] Ambil subdomain {domain}: {e}")
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
        print(f"[ERROR] Cek umur {subdomain}: {e}")
    return False, None

def check_http(subdomain):
    url = f"http://{subdomain}"
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No Title"
        return r.status_code, title
    except:
        return None, "Tidak dapat diakses"

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
        params = {
            "query": domain,
            "apiKey": VULNERS_API_KEY
        }
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

def run():
    checked = load_checked()

    while True:
        for domain in DOMAIN_LIST:
            if domain not in checked:
                checked[domain] = []

            print(f"[INFO] Mengecek domain: {domain}")
            subdomains = get_subdomains(domain)

            for sub in subdomains:
                if sub in checked[domain]:
                    continue

                recent, tgl = is_recent(sub)
                if recent:
                    status, title = check_http(sub)
                    ip = resolve_ip(sub)

                    if ip:
                        shodan_cves = get_cve_shodan(ip)
                    else:
                        shodan_cves = []

                    vulners_cves = get_cve_vulners(sub)
                    cve_result = format_cve_list(shodan_cves, vulners_cves)

                    message = (
                        f"🔔 *{domain} - Subdomain baru terdeteksi!*\n"
                        f"`{sub}`\n📅 Aktif: {tgl}\n"
                        f"📄 Status: `{status}`\n📝 Title: *{title}*\n"
                        f"\n*CVEs:*\n{cve_result if cve_result else 'Tidak ditemukan'}"
                    )
                    print(message)
                    send_telegram(message)

                checked[domain].append(sub)

            save_checked(checked)

            print(f"[INFO] Selesai cek domain {domain}. Menunggu 1 menit sebelum domain berikutnya...\n")
            time.sleep(60)  # Delay antar domain

        print(f"[INFO] Selesai cek semua domain. Tidur {SLEEP_INTERVAL // 60} menit...\n")
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    run()
