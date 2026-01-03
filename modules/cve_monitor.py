"""
THE WATCHTOWER - CVE Monitor Module
NVD API'sini dinler, yeni kritik CVE'leri yakalar ve trigger atar.
"""

import requests
import time
import json
from datetime import datetime
from typing import Callable, Optional, List, Dict, Set


class CVEMonitor:
    """NVD API'yi izleyen ve yeni CVE'leri yakalayan sınıf"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.seen_cves: Set[str] = set()
        self.callbacks: List[Callable] = []
        
    def add_callback(self, callback: Callable):
        """Yeni CVE geldiğinde çağrılacak fonksiyon ekle"""
        self.callbacks.append(callback)
        
    def _trigger_callbacks(self, cve_data: Dict):
        """Tüm callback'leri tetikle"""
        for callback in self.callbacks:
            try:
                callback(cve_data)
            except Exception as e:
                print(f"⚠️ Callback hatası: {e}")
    
    def format_cve(self, vuln: Dict) -> Dict:
        """CVE verisini standart formata çevir"""
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "N/A")
        
        # Description
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available")
        
        # CVSS Score
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        
        # Affected Software
        affected_software = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    criteria = cpe.get("criteria", "")
                    if criteria:
                        parts = criteria.split(":")
                        if len(parts) >= 6:
                            vendor = parts[3]
                            product = parts[4]
                            
                            version_info = ""
                            if cpe.get("versionEndExcluding"):
                                version_info = f"< {cpe.get('versionEndExcluding')}"
                            elif cpe.get("versionEndIncluding"):
                                version_info = f"<= {cpe.get('versionEndIncluding')}"
                            elif parts[5] and parts[5] != "*":
                                version_info = parts[5]
                            
                            software_name = f"{product}"
                            if version_info:
                                software_name += f" {version_info}"
                            
                            if software_name not in affected_software:
                                affected_software.append(software_name)
        
        return {
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": cvss_score,
            "severity": severity,
            "affected_software": affected_software if affected_software else ["Not specified"],
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", "")
        }
    
    def fetch_critical_cves(self, year: str = "2025") -> List[Dict]:
        """Belirli yılın kritik CVE'lerini çek"""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": 2000,
            "startIndex": 0
        }
        
        all_cves = []
        
        while True:
            try:
                response = requests.get(self.base_url, headers=headers, params=params, timeout=60)
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    for vuln in vulnerabilities:
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id", "")
                        if cve_id.startswith(f"CVE-{year}"):
                            formatted = self.format_cve(vuln)
                            all_cves.append(formatted)
                            self.seen_cves.add(cve_id)
                    
                    total_results = data.get("totalResults", 0)
                    print(f"  İşlendi: {params['startIndex'] + len(vulnerabilities)}/{total_results}")
                    
                    if params["startIndex"] + len(vulnerabilities) >= total_results:
                        break
                    
                    params["startIndex"] += 2000
                    time.sleep(6 if not self.api_key else 0.6)
                else:
                    print(f"⚠️ API Hatası: {response.status_code}")
                    break
                    
            except requests.exceptions.RequestException as e:
                print(f"⚠️ Bağlantı hatası: {e}")
                break
        
        return all_cves
    
    def check_for_new_cves(self, year: str = "2025") -> List[Dict]:
        """Yeni CVE'leri kontrol et ve callback'leri tetikle"""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": 100,
            "startIndex": 0
        }
        
        new_cves = []
        
        try:
            response = requests.get(self.base_url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    
                    if cve_id.startswith(f"CVE-{year}") and cve_id not in self.seen_cves:
                        self.seen_cves.add(cve_id)
                        formatted = self.format_cve(vuln)
                        new_cves.append(formatted)
                        
                        # TRIGGER!
                        self._trigger_callbacks(formatted)
                        
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Bağlantı hatası: {e}")
        
        return new_cves
    
    def start_monitoring(self, interval: int = 7, year: str = "2025"):
        """
        Sürekli izleme başlat
        interval: Kontrol aralığı (saniye)
        """
        print("="*80)
        print("🔍 SENTILLM - THE WATCHTOWER BAŞLATILIYOR")
        print(f"⏱️  Kontrol aralığı: {interval} saniye")
        print("="*80 + "\n")
        
        # Önce mevcut CVE'leri yükle
        print("📂 Mevcut kritik CVE'ler yükleniyor...")
        existing = self.fetch_critical_cves(year)
        print(f"✅ {len(self.seen_cves)} adet CVE-{year} yüklendi.\n")
        
        print("🔄 Yeni kritik CVE'ler için izleme başladı...")
        print("   Çıkmak için Ctrl+C\n")
        
        check_count = 0
        
        try:
            while True:
                check_count += 1
                timestamp = datetime.now().strftime('%H:%M:%S')
                
                new_cves = self.check_for_new_cves(year)
                
                if not new_cves:
                    print(f"[{timestamp}] Kontrol #{check_count} - Yeni CVE yok. Toplam: {len(self.seen_cves)}", end='\r')
                else:
                    print(f"\n[{timestamp}] 🚨 {len(new_cves)} YENİ CVE TESPİT EDİLDİ!")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print(f"\n\n🛑 Monitör durduruldu. Toplam {len(self.seen_cves)} CVE izlendi.")


# Test için
if __name__ == "__main__":
    import dotenv
    api_key = dotenv.get_key(dotenv.find_dotenv(), "NVD_API_KEY")
    
    monitor = CVEMonitor(api_key)
    
    # Örnek callback
    def on_new_cve(cve_data):
        print(f"\n🚨 YENİ CVE: {cve_data['cve_id']}")
        print(json.dumps(cve_data, indent=2, ensure_ascii=False))
    
    monitor.add_callback(on_new_cve)
    monitor.start_monitoring(interval=7)