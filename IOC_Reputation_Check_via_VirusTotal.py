"""[Python] IOC Reputation Check via VirusTotal (Public API)
Senaryo:
Bir analist olarak, topladığınız şüpheli IP adreslerini hızlıca değerlendirmek istiyorsunuz. VirusTotal Public API anahtarınız mevcut (rate limit’li olsa da uygun).
Görev:
Python kullanarak aşağıdaki adımları gerçekleştiren bir script yazınız:
•	ips.txt dosyasını oku (her satırda bir IP olacak)
•	Her IP için VirusTotal Public API’sine sorgu gönder
•	Gelen JSON cevabındaki malicious veya suspicious kategorileri 1 veya daha fazla ise:
o	IP’yi malicious_ips.txt içine yaz
•	API yanıtı bulunamazsa not_found_ips.txt içine yaz
•	Yanıtları JSON formatında responses/ klasörüne kaydet
"""

import requests
import json
import os
import time
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_API_URL_IP = "https://www.virustotal.com/api/v3/ip_addresses/{}"
REQUEST_DELAY = 16

def check_ip_reputation(ip_address):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = VT_API_URL_IP.format(ip_address)
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            return {"error": "not_found", "status_code": 404}
        print(f"HTTP hatası: {http_err} - IP: {ip_address}")
        return {"error": str(http_err), "status_code": response.status_code if 'response' in locals() else 'unknown'}
    except requests.exceptions.RequestException as req_err:
        print(f"İstek hatası: {req_err} - IP: {ip_address}")
        return {"error": str(req_err), "status_code": "request_error"}
    except json.JSONDecodeError as json_err:
        print(f"JSON decode hatası: {json_err} - IP: {ip_address}")
        return {"error": "json_decode_error"}

def main():
    os.makedirs("responses", exist_ok=True)
    input_ips_file = "ips.txt"
    malicious_ips_file = "malicious_ips.txt"
    not_found_ips_file = "not_found_ips.txt"

    if not os.path.exists(input_ips_file):
        print(f"Hata: '{input_ips_file}' bulunamadı.")
        return

    with open(malicious_ips_file, 'w') as f_malicious, open(not_found_ips_file, 'w') as f_not_found, open(input_ips_file, 'r') as f_ips:
        ip_addresses = [line.strip() for line in f_ips if line.strip()]
        if not ip_addresses:
            print(f"'{input_ips_file}' içinde IP adresi yok.")
            return

        print(f"Toplam {len(ip_addresses)} IP adresi işlenecek...")
        for ip in ip_addresses:
            print(f"\n{ip} sorgulanıyor...")
            vt_response = check_ip_reputation(ip)
            response_filename = os.path.join("responses", f"{ip.replace('.', '_')}_response.json")
            with open(response_filename, 'w') as f_json:
                json.dump(vt_response, f_json, indent=4)
            print(f"Yanıt '{response_filename}' dosyasına kaydedildi.")

            if vt_response and "data" in vt_response:
                stats = vt_response["data"].get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0 or suspicious > 0:
                    print(f"IP {ip} zararlı/şüpheli (Malicious: {malicious}, Suspicious: {suspicious}).")
                    f_malicious.write(ip + "\n")
                else:
                    print(f"IP {ip} temiz (Malicious: {malicious}, Suspicious: {suspicious}).")
            elif vt_response and vt_response.get("error") == "not_found":
                print(f"IP {ip} VirusTotal'da bulunamadı.")
                f_not_found.write(ip + "\n")
            else:
                print(f"IP {ip} için yanıt alınamadı/hata oluştu. Detaylar: {response_filename}")
            
            if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "YOUR_VIRUSTOTAL_API_KEY":
                print(f"{REQUEST_DELAY} saniye bekleniyor...")
                time.sleep(REQUEST_DELAY)
            else:
                print("Uyarı: Geçerli API anahtarı girilmedi.")

    print("\nİşlem tamamlandı.")
    print(f"Zararlı IP'ler: '{malicious_ips_file}'")
    print(f"Bulunamayan IP'ler: '{not_found_ips_file}'")
    print(f"Yanıtlar: 'responses/' klasörü")

if __name__ == "__main__":
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        print("Lütfen .env dosyasında VIRUSTOTAL_API_KEY değerini kendi VirusTotal API anahtarınızla ayarlayın.")
    else:
        main()

