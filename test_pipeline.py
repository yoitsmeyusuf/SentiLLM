"""
SentiLLM - End-to-End Pipeline Test
Mock CVE ile tüm sistemi test eder.

Test Senaryosu:
1. Mock CVE oluştur (requests kütüphanesinde sahte bir açık)
2. SentiLLM reposunu tara
3. CVE ile bağımlılıkları eşleştir  
4. AI Agent analiz yapsın
5. GitHub Issue oluştur (dry-run)
"""

import os
import sys
import json
from datetime import datetime

# Modules klasörünü path'e ekle
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from dotenv import load_dotenv
load_dotenv()


# ================================================================
# MOCK CVE VERİLERİ
# ================================================================

MOCK_CVES = [
    {
        "cve_id": "CVE-2025-99999",
        "description": "A critical vulnerability in requests library allows remote attackers to perform SSRF attacks via malformed URLs. Versions before 2.32.0 are affected.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected_software": ["requests < 2.32.0"],
        "published_date": "2025-01-02",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-99999",
            "https://github.com/psf/requests/security/advisories/GHSA-xxxx-xxxx-xxxx"
        ],
        "cwe": "CWE-918",
        "attack_vector": "NETWORK",
        "remediation": "Upgrade requests to version 2.32.0 or later"
    },
    {
        "cve_id": "CVE-2025-88888",
        "description": "python-dotenv before 1.0.1 has a path traversal vulnerability that allows reading arbitrary files when loading .env from untrusted sources.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected_software": ["python-dotenv < 1.0.1"],
        "published_date": "2025-01-01",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-88888"
        ],
        "cwe": "CWE-22",
        "attack_vector": "LOCAL",
        "remediation": "Upgrade python-dotenv to version 1.0.1 or later"
    },
    {
        "cve_id": "CVE-2025-77777",
        "description": "transformers library has a deserialization vulnerability when loading untrusted model files. Remote code execution is possible.",
        "severity": "CRITICAL", 
        "cvss_score": 9.1,
        "affected_software": ["transformers < 4.40.0"],
        "published_date": "2025-01-03",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-77777",
            "https://huggingface.co/security"
        ],
        "cwe": "CWE-502",
        "attack_vector": "NETWORK",
        "remediation": "Upgrade transformers to version 4.40.0 or later. Use trust_remote_code=False"
    }
]


def print_header(title: str):
    """Başlık yazdır"""
    print(f"\n{'='*60}")
    print(f"🧪 {title}")
    print(f"{'='*60}")


def test_rag_memory():
    """RAG Memory modülünü test et"""
    print_header("TEST 1: RAG Memory - Repo Tarama")
    
    try:
        from rag_memory import RAGMemory
        
        memory = RAGMemory()
        
        # GitHub token ayarla (varsa)
        token = os.getenv("GITHUB_TOKEN")
        if token:
            memory.set_github_token(token)
            print("✅ GitHub token ayarlandı")
        else:
            print("⚠️ GitHub token bulunamadı (rate limit olabilir)")
        
        # Kendi repomuzu tara
        print("\n📥 SentiLLM reposu taranıyor...")
        result = memory.ingest_github_repo(
            "https://github.com/yoitsmeyusuf/SentiLLM",
            recursive=True,
            max_depth=2
        )
        
        if result.get("error"):
            # Repo henüz GitHub'da yoksa local dosyayı oku
            print("⚠️ GitHub'dan okunamadı, local requirements.txt okunuyor...")
            
            req_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
            if os.path.exists(req_path):
                with open(req_path, "r") as f:
                    content = f.read()
                deps = memory.parse_requirements_txt(content)
                result = {
                    "repo": "local/SentiLLM",
                    "total_dependencies": len(deps),
                    "dependencies": deps
                }
                print(f"✅ Local'den {len(deps)} bağımlılık okundu")
        else:
            print(f"✅ GitHub'dan {result.get('total_dependencies', 0)} bağımlılık bulundu")
        
        return result
        
    except Exception as e:
        print(f"❌ RAG Memory hatası: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_cve_matching(dependencies: list):
    """Mock CVE'leri bağımlılıklarla eşleştir"""
    print_header("TEST 2: CVE Eşleştirme")
    
    matches = []
    
    for cve in MOCK_CVES:
        print(f"\n🔍 {cve['cve_id']} kontrol ediliyor...")
        print(f"   Affected: {cve['affected_software']}")
        
        for affected in cve['affected_software']:
            # "requests < 2.32.0" formatından paket adını çıkar
            pkg_name = affected.split()[0].lower()
            
            for dep in dependencies:
                dep_name = dep.get("name", "").lower()
                dep_version = dep.get("version", "latest")
                
                if pkg_name == dep_name:
                    print(f"   ⚠️ EŞLEŞME: {dep_name} v{dep_version}")
                    matches.append({
                        "cve": cve,
                        "dependency": dep,
                        "affected_spec": affected
                    })
    
    if matches:
        print(f"\n🚨 {len(matches)} güvenlik açığı bulundu!")
    else:
        print("\n✅ Güvenlik açığı bulunamadı")
    
    return matches


def test_ai_agent(matches: list):
    """AI Agent'ı test et (analiz)"""
    print_header("TEST 3: AI Agent Analiz")
    
    if not matches:
        print("⚠️ Eşleşme yok, analiz atlanıyor")
        return []
    
    try:
        from ai_agent import SecurityAgent
        
        # SentiLLM model path - HuggingFace'den yükle
        SENTILLM_MODEL = "yoitsmeyusuf/sentillm-cve-analyzer-lora"
        
        # Environment'dan da alınabilir
        model_path = os.getenv("SENTILLM_MODEL", SENTILLM_MODEL)
        openai_key = os.getenv("OPENAI_API_KEY")
        
        print(f"📦 SentiLLM Model: {model_path}")
        
        agent = SecurityAgent(
            sentillm_model_path=model_path,
            openai_api_key=openai_key
        )
        
        # Backend bilgisi
        if agent.sentillm_model:
            backend = "SentiLLM"
        elif agent.openai_client:
            backend = "OpenAI"
        else:
            backend = "Rule-based"
        print(f"✅ AI Agent yüklendi (Backend: {backend})")
        
        analyses = []
        
        for match in matches[:2]:  # İlk 2 eşleşmeyi analiz et
            cve = match["cve"]
            dep = match["dependency"]
            
            print(f"\n🤖 {cve['cve_id']} analiz ediliyor...")
            
            # Analiz yap - doğru metod: analyze_vulnerability
            analysis = agent.analyze_vulnerability(cve, dep)
            
            if analysis:
                print(f"   Risk: {analysis.get('risk_level', 'N/A')}")
                print(f"   Priority: {analysis.get('priority', 'N/A')}")
                analyses.append({
                    "cve": cve,
                    "dependency": dep,
                    "analysis": analysis
                })
            else:
                print("   ⚠️ Analiz başarısız")
        
        return analyses
        
    except Exception as e:
        print(f"❌ AI Agent hatası: {e}")
        import traceback
        traceback.print_exc()
        return []


def test_github_integration(analyses: list, dry_run: bool = True):
    """GitHub Issue oluşturma testi"""
    print_header("TEST 4: GitHub Integration")
    
    if not analyses:
        print("⚠️ Analiz yok, GitHub testi atlanıyor")
        return
    
    if dry_run:
        print("🔒 DRY-RUN modu: Gerçek Issue oluşturulmayacak\n")
    
    try:
        from ai_agent import SecurityAgent
        
        github_token = os.getenv("GITHUB_TOKEN")
        agent = SecurityAgent(github_token=github_token)
        
        for item in analyses:
            cve = item["cve"]
            analysis = item["analysis"]
            dep = item["dependency"]
            
            # Issue içeriği oluştur
            issue_title = f"🔒 Security Alert: {cve['cve_id']} - {dep['name']}"
            
            issue_body = f"""## Security Vulnerability Detected

**CVE ID:** {cve['cve_id']}
**Severity:** {cve['severity']} (CVSS: {cve['cvss_score']})
**Published:** {cve['published_date']}

### Affected Dependency
- **Package:** `{dep['name']}`
- **Current Version:** `{dep['version']}`
- **Affected Versions:** {', '.join(cve['affected_software'])}

### Description
{cve['description']}

### AI Analysis
- **Risk Level:** {analysis.get('risk_level', 'N/A')}
- **Priority:** {analysis.get('priority', 'N/A')}
- **Recommendation:** {analysis.get('recommendation', cve['remediation'])}

### Remediation
{cve['remediation']}

### References
{chr(10).join(['- ' + ref for ref in cve['references']])}

---
*This issue was automatically generated by SentiLLM Security Agent*
"""
            
            print(f"📝 Issue: {issue_title}")
            print("-" * 50)
            print(issue_body[:500] + "..." if len(issue_body) > 500 else issue_body)
            print("-" * 50)
            
            if not dry_run:
                # Gerçek Issue oluştur
                if github_token:
                    # Analysis'i agent formatına çevir
                    agent_analysis = {
                        "cve_id": cve['cve_id'],
                        "dependency": dep['name'],
                        "current_version": dep['version'],
                        "risk_level": analysis.get('risk_level', 'N/A'),
                        "reason": analysis.get('reason', cve['description']),
                        "action_required": cve['remediation'],
                        "recommended_version": "latest"
                    }
                    
                    result = agent.create_github_issue(
                        repo_full_name="yoitsmeyusuf/SentiLLM",
                        analysis=agent_analysis,
                        cve_data=cve
                    )
                    if result:
                        print(f"✅ Issue oluşturuldu: {result}")
                    else:
                        print("❌ Issue oluşturulamadı")
                else:
                    print("⚠️ GITHUB_TOKEN bulunamadı")
            else:
                print("🔒 [DRY-RUN] Issue oluşturulmadı\n")
                
    except Exception as e:
        print(f"❌ GitHub Integration hatası: {e}")
        import traceback
        traceback.print_exc()


def run_full_pipeline(dry_run: bool = True):
    """Tüm pipeline'ı çalıştır"""
    print("\n" + "="*60)
    print("🚀 SentiLLM END-TO-END PIPELINE TEST")
    print("="*60)
    print(f"📅 Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🔒 Dry-run: {dry_run}")
    print("="*60)
    
    # Test 1: RAG Memory
    result = test_rag_memory()
    
    if not result:
        print("\n❌ Pipeline başarısız: RAG Memory hatası")
        return
    
    dependencies = result.get("dependencies", [])
    
    if not dependencies:
        print("\n❌ Pipeline başarısız: Bağımlılık bulunamadı")
        return
    
    print(f"\n📦 Bulunan bağımlılıklar ({len(dependencies)}):")
    for dep in dependencies[:10]:
        print(f"   - {dep['name']} v{dep['version']}")
    if len(dependencies) > 10:
        print(f"   ... ve {len(dependencies) - 10} daha")
    
    # Test 2: CVE Matching
    matches = test_cve_matching(dependencies)
    
    # Test 3: AI Agent
    analyses = test_ai_agent(matches)
    
    # Test 4: GitHub Integration
    test_github_integration(analyses, dry_run=dry_run)
    
    # Özet
    print_header("PIPELINE SONUCU")
    print(f"✅ Taranan bağımlılık: {len(dependencies)}")
    print(f"🚨 Bulunan güvenlik açığı: {len(matches)}")
    print(f"🤖 Analiz edilen: {len(analyses)}")
    print(f"📝 Issue hazırlandı: {len(analyses)}")
    
    if dry_run:
        print("\n💡 Gerçek Issue oluşturmak için: python test_pipeline.py --live")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SentiLLM Pipeline Test")
    parser.add_argument("--live", action="store_true", help="Gerçek GitHub Issue oluştur")
    args = parser.parse_args()
    
    run_full_pipeline(dry_run=not args.live)
