import requests
import time

TELEGRAM_BOT_TOKEN = "7694882683:AAFaJk1-ZS22Hl1p7V_8wz7lJse43MJdues"
TELEGRAM_CHAT_ID = "1632789720"
DOMAIN = "nasa.gov"

def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        data = r.json()
        subdomains = set()
        for entry in data:
            name_value = entry['name_value']
            subdomains.update(name_value.split("\n"))
        return list(subdomains)
    except Exception as e:
        print(f"[ERROR] Gagal ambil data: {e}")
        return []

def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message
        }
        requests.get(url, params=payload)
    except Exception as e:
        print(f"[ERROR] Kirim Telegram gagal: {e}")

# INIT
known_subdomains = set(get_subdomains(DOMAIN))
print(f"[INIT] Ditemukan {len(known_subdomains)} subdomain awal.")

while True:
    try:
        current_subdomains = set(get_subdomains(DOMAIN))
        new_subs = current_subdomains - known_subdomains

        if new_subs:
            for sub in new_subs:
                msg = f"[⚠️ SUBDOMAIN BARU TERDETEKSI]\n{sub}"
                print(msg)
                send_telegram(msg)
            known_subdomains = current_subdomains

        time.sleep(3600)  # cek tiap 1 jam
    except Exception as e:
        print(f"[ERROR LOOP] {e}")
        time.sleep(600)
