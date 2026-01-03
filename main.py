"""
SENTILLM - ORKESTRA ŞEFİ
Tüm modülleri birleştirir ve koordine eder.

Akış:
1. CVE Monitor → Yeni CVE tespit et
2. RAG Memory → Projedeki bağımlılıklarla eşleştir  
3. AI Agent → Analiz et ve aksiyon al
"""

import os
import json
import time
from datetime import datetime
from typing import List, Dict, Optional

import dotenv
dotenv.load_dotenv()

from modules.cve_monitor import CVEMonitor
from modules.rag_memory import RAGMemory
from modules.ai_agent import SecurityAgent


class SentiLLM:
    """Ana orkestrasyon sınıfı"""
    
    def __init__(self):
        # API Key'leri yükle
        self.nvd_api_key = os.getenv("NVD_API_KEY")
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        
        # Modülleri başlat
        self.monitor = CVEMonitor(api_key=self.nvd_api_key)
        self.memory = RAGMemory(db_path="./data/chromadb")
        self.agent = SecurityAgent(
            openai_api_key=self.openai_api_key,
            github_token=self.github_token
        )
        
        # GitHub token'ı memory'ye de ver
        if self.github_token:
            self.memory.set_github_token(self.github_token)
        
        # İzlenen repolar
        self.watched_repos: List[str] = []
        
        # Sonuçları kaydet
        self.results_log: List[Dict] = []
        
    def add_repo(self, repo_url: str) -> Dict:
        """İzlenecek repo ekle ve bağımlılıklarını analiz et"""
        print(f"\n📦 Repo ekleniyor: {repo_url}")
        
        result = self.memory.ingest_github_repo(repo_url)
        
        if "error" not in result:
            self.watched_repos.append(result.get("repo", repo_url))
            print(f"✅ {result.get('repo')} başarıyla eklendi.")
        
        return result
    
    def on_new_cve(self, cve_data: Dict):
        """Yeni CVE geldiğinde çalışan callback"""
        print("\n" + "="*80)
        print(f"🚨 YENİ KRİTİK CVE: {cve_data.get('cve_id')}")
        print(f"   Severity: {cve_data.get('severity')} | CVSS: {cve_data.get('cvss_score')}")
        print("="*80)
        
        # CVE'yi kayıtlı bağımlılıklarla eşleştir
        matches = self.memory.match_cve_with_dependencies(cve_data)
        
        if not matches:
            print("   ✅ İzlenen projelerde eşleşme bulunamadı.")
            return
        
        print(f"   ⚠️ {len(matches)} potansiyel eşleşme bulundu!")
        
        # Her eşleşme için analiz yap
        for match in matches:
            dep = match.get("matched_dependency", {})
            
            result = self.agent.process_vulnerability(
                cve_data=cve_data,
                matched_dependency=dep,
                auto_fix=False  # Güvenlik için default False
            )
            
            self.results_log.append({
                "timestamp": datetime.now().isoformat(),
                **result
            })
            
            # Sonuçları dosyaya kaydet
            self._save_results()
    
    def _save_results(self):
        """Sonuçları JSON dosyasına kaydet"""
        os.makedirs("./data", exist_ok=True)
        with open("./data/scan_results.json", "w", encoding="utf-8") as f:
            json.dump(self.results_log, f, indent=2, ensure_ascii=False)
    
    def scan_existing_cves(self, year: str = "2025") -> List[Dict]:
        """Mevcut kritik CVE'leri tara ve eşleştir"""
        print(f"\n🔍 {year} yılı kritik CVE'leri taranıyor...")
        
        # Kritik CVE'leri çek
        cves = self.monitor.fetch_critical_cves(year)
        print(f"   Toplam {len(cves)} kritik CVE bulundu.")
        
        # Tüm bağımlılıkları al
        all_deps = self.memory.get_all_dependencies()
        
        if not all_deps:
            print("   ⚠️ Kayıtlı bağımlılık yok. Önce repo ekleyin.")
            return []
        
        print(f"   {len(all_deps)} kayıtlı bağımlılık kontrol ediliyor...")
        
        vulnerabilities = []
        
        for cve in cves:
            matches = self.memory.match_cve_with_dependencies(cve)
            
            for match in matches:
                dep = match.get("matched_dependency", {})
                analysis = self.agent.analyze_vulnerability(cve, dep)
                
                if analysis.get("vulnerable"):
                    vulnerabilities.append({
                        "cve": cve,
                        "dependency": dep,
                        "analysis": analysis
                    })
        
        print(f"\n🚨 Toplam {len(vulnerabilities)} güvenlik açığı tespit edildi!")
        return vulnerabilities
    
    def start_monitoring(self, interval: int = 7):
        """Sürekli izleme başlat"""
        print("\n" + "="*80)
        print("🛡️  SENTILLM - SECURITY MONITORING SYSTEM")
        print("="*80)
        print(f"📡 İzlenen Repolar: {len(self.watched_repos)}")
        for repo in self.watched_repos:
            print(f"   - {repo}")
        print("="*80 + "\n")
        
        # Callback'i bağla
        self.monitor.add_callback(self.on_new_cve)
        
        # İzlemeyi başlat
        self.monitor.start_monitoring(interval=interval)
    
    def run_demo(self):
        """Demo modu - Hızlı test için"""
        print("\n" + "="*80)
        print("🎮 SENTILLM DEMO MODU")
        print("="*80 + "\n")
        
        # 1. Örnek repo ekle
        print("ADIM 1: Repo Analizi")
        print("-"*40)
        self.add_repo("https://github.com/pallets/flask")
        
        # 2. Mevcut CVE'leri tara
        print("\nADIM 2: Güvenlik Taraması")
        print("-"*40)
        vulns = self.scan_existing_cves("2025")
        
        # 3. Sonuçları göster
        print("\nADIM 3: Sonuçlar")
        print("-"*40)
        
        if vulns:
            for i, vuln in enumerate(vulns[:5], 1):  # İlk 5
                print(f"\n{i}. {vuln['cve']['cve_id']}")
                print(f"   Bağımlılık: {vuln['dependency'].get('name')} v{vuln['dependency'].get('version')}")
                print(f"   Risk: {vuln['analysis'].get('risk_level')}")
        else:
            print("✅ Güvenlik açığı bulunamadı!")
        
        print("\n" + "="*80)
        print("Demo tamamlandı. Gerçek izleme için: sentillm.start_monitoring()")
        print("="*80)


def main():
    """Ana giriş noktası"""
    import sys
    
    sentillm = SentiLLM()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "demo":
            sentillm.run_demo()
            
        elif command == "monitor":
            # Önce repoları ekle
            if len(sys.argv) > 2:
                for repo_url in sys.argv[2:]:
                    sentillm.add_repo(repo_url)
            sentillm.start_monitoring()
            
        elif command == "add":
            if len(sys.argv) > 2:
                sentillm.add_repo(sys.argv[2])
            else:
                print("Kullanım: python main.py add <github_repo_url>")
                
        elif command == "scan":
            if len(sys.argv) > 2:
                sentillm.add_repo(sys.argv[2])
            sentillm.scan_existing_cves()
            
        else:
            print("Kullanım:")
            print("  python main.py demo                    - Demo modu")
            print("  python main.py monitor [repo_urls...]  - Sürekli izleme")
            print("  python main.py add <repo_url>          - Repo ekle")
            print("  python main.py scan [repo_url]         - Tek seferlik tarama")
    else:
        # Varsayılan: Demo
        sentillm.run_demo()


if __name__ == "__main__":
    main()
