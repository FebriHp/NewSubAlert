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
DOMAIN_LIST = ["nasa.gov"]
CHECKED_FILE = "checked.json"
SLEEP_INTERVAL = 3600  # waktu tunggu antar pengecekan (dalam detik) - 1 jam
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
                    message = (
                        f"🔔 *{domain} - Subdomain baru terdeteksi!*\n"
                        f"`{sub}`\n📅 Aktif: {tgl}\n"
                        f"📄 Status: `{status}`\n📝 Title: *{title}*"
                    )
                    print(message)
                    send_telegram(message)

                # Tambahkan ke list yang sudah dicek
                checked[domain].append(sub)

            save_checked(checked)

        print(f"[INFO] Selesai cek semua domain. Tidur {SLEEP_INTERVAL // 60} menit...\n")
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    run()
