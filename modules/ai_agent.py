"""
THE BRAIN & THE AGENT - AI Agent Module
SentiLLM (Fine-tuned Llama-3-8B) ile CVE analizi yapar ve GitHub'da Issue/PR açar.
"""

import os
import re
import json
import requests
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    from github import Github, GithubException
    PYGITHUB_AVAILABLE = True
except ImportError:
    PYGITHUB_AVAILABLE = False
    print("⚠️ PyGithub yüklü değil. 'pip install PyGithub' ile yükleyin.")

# SentiLLM Model Loading (Windows uyumlu - transformers + PEFT)
SENTILLM_AVAILABLE = False
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import PeftModel
    SENTILLM_AVAILABLE = True
    TORCH_AVAILABLE = True
except ImportError as e:
    TORCH_AVAILABLE = False
    print(f"⚠️ Transformers/PEFT yüklü değil: {e}")
    print("   pip install transformers peft accelerate bitsandbytes")

# Fallback: OpenAI API (opsiyonel)
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class SecurityAgent:
    """CVE analizi yapan ve GitHub'da aksiyon alan AI Agent - SentiLLM Powered"""
    
    # SentiLLM Prompt Template (Training ile aynı format)
    ALPACA_PROMPT = """Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

### Metadata:
- Scenario: {scenario}
- Language: {language}
- Expected Result: {expected_result}

### Instruction:
{instruction}

### Input:
{input}

### Response:
{output}"""
    
    def __init__(
        self,
        sentillm_model_path: Optional[str] = None,  # HuggingFace model ID veya lokal path
        github_token: Optional[str] = None,
        openai_api_key: Optional[str] = None,  # Fallback için
        use_gpu: bool = True
    ):
        self.github_token = github_token
        self.openai_api_key = openai_api_key
        self.use_gpu = use_gpu
        
        # SentiLLM Model (Primary)
        self.sentillm_model = None
        self.sentillm_tokenizer = None
        
        if SENTILLM_AVAILABLE and sentillm_model_path:
            self._load_sentillm(sentillm_model_path)
        
        # OpenAI Fallback
        if OPENAI_AVAILABLE and openai_api_key and not self.sentillm_model:
            self.openai_client = OpenAI(api_key=openai_api_key)
        else:
            self.openai_client = None
        
        # GitHub Client
        if PYGITHUB_AVAILABLE and github_token:
            self.github = Github(github_token)
        else:
            self.github = None
    
    def _load_sentillm(self, model_path: str):
        """SentiLLM modelini yükle (Windows uyumlu - transformers + PEFT)"""
        try:
            print(f"🦙 SentiLLM yükleniyor: {model_path}")
            
            # GPU kontrolü
            if torch.cuda.is_available():
                print(f"   GPU: {torch.cuda.get_device_name(0)}")
                device = "cuda"
            else:
                print("   ⚠️ GPU bulunamadı, CPU kullanılacak (yavaş)")
                device = "cpu"
            
            # 4-bit quantization config (GPU varsa)
            if device == "cuda":
                bnb_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_quant_type="nf4",
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_use_double_quant=True,
                )
            else:
                bnb_config = None
            
            # Base model (Llama-3-8B)
            base_model_id = "meta-llama/Meta-Llama-3-8B"
            
            print(f"   Base model: {base_model_id}")
            
            # Tokenizer yükle
            self.sentillm_tokenizer = AutoTokenizer.from_pretrained(
                model_path,
                trust_remote_code=True
            )
            
            # Model yükle
            if bnb_config:
                # GPU ile 4-bit quantized
                base_model = AutoModelForCausalLM.from_pretrained(
                    base_model_id,
                    quantization_config=bnb_config,
                    device_map="auto",
                    trust_remote_code=True,
                )
            else:
                # CPU (quantization yok)
                base_model = AutoModelForCausalLM.from_pretrained(
                    base_model_id,
                    torch_dtype=torch.float32,
                    device_map="cpu",
                    trust_remote_code=True,
                )
            
            # LoRA adaptörlerini yükle
            print(f"   LoRA adapters: {model_path}")
            self.sentillm_model = PeftModel.from_pretrained(
                base_model,
                model_path,
                device_map="auto" if device == "cuda" else "cpu"
            )
            
            # Eval mode
            self.sentillm_model.eval()
            
            print("✅ SentiLLM yüklendi!")
            
        except Exception as e:
            print(f"⚠️ SentiLLM yüklenemedi: {e}")
            print("   OpenAI fallback kullanılacak...")
            self.sentillm_model = None
            self.sentillm_tokenizer = None
            
            print("✅ SentiLLM yüklendi!")
            
        except Exception as e:
            print(f"⚠️ SentiLLM yüklenemedi: {e}")
            self.sentillm_model = None
            self.sentillm_tokenizer = None
    
    def analyze_vulnerability(
        self,
        cve_data: Dict,
        matched_dependency: Dict
    ) -> Dict:
        """
        THE BRAIN: SentiLLM kullanarak CVE'nin projeyi etkileyip etkilemediğini analiz et
        """
        cve_id = cve_data.get("cve_id", "Unknown")
        description = cve_data.get("description", "No description")
        affected = cve_data.get("affected_software", [])
        cvss_score = cve_data.get("cvss_score", "N/A")
        severity = cve_data.get("severity", "N/A")
        
        dep_name = matched_dependency.get("name", "Unknown")
        dep_version = matched_dependency.get("version", "Unknown")
        dep_repo = matched_dependency.get("repo", "Unknown")
        dep_file_type = matched_dependency.get("file_type", "requirements.txt")
        
        # Dosya tipi -> Dil eşlemesi
        language_map = {
            "requirements.txt": "Python",
            "package.json": "JavaScript",
            "pom.xml": "Java",
            "build.gradle": "Java",
            "Gemfile": "Ruby",
            "go.mod": "Go",
            "Cargo.toml": "Rust",
            "composer.json": "PHP"
        }
        language = language_map.get(dep_file_type, "mixed")
        
        # SentiLLM Prompt (Training format ile aynı)
        instruction = f"""You are a Senior Product Security Engineer. Analyze the provided 'CVE Intelligence Report' and the 'Dependency File'. 
1. Determine if the project is vulnerable based on Semantic Versioning rules.
2. Ignore comments and unrelated libraries in the file.
3. Provide a strictly valid JSON response containing the risk assessment, reasoning, and remediation command."""
        
        input_text = f"""--- CVE INTELLIGENCE REPORT ---
CVE ID: {cve_id}
Title: {description[:100]}
Severity: {severity} (CVSS {cvss_score})
Affected Versions: {', '.join(affected) if affected else 'Not specified'}
Description: {description}

--- TARGET DEPENDENCY ---
Package: {dep_name}
Current Version: {dep_version}
Repository: {dep_repo}
"""
        
        # SentiLLM ile analiz (Primary)
        if self.sentillm_model and self.sentillm_tokenizer:
            return self._analyze_with_sentillm(
                instruction=instruction,
                input_text=input_text,
                language=language,
                cve_id=cve_id,
                dep_name=dep_name,
                dep_version=dep_version,
                dep_repo=dep_repo
            )
        
        # OpenAI Fallback
        elif self.openai_client:
            return self._analyze_with_openai(
                instruction=instruction,
                input_text=input_text,
                cve_id=cve_id,
                dep_name=dep_name,
                dep_version=dep_version,
                dep_repo=dep_repo
            )
        
        # Kural tabanlı fallback
        return self._rule_based_analysis(cve_data, matched_dependency)
    
    def _analyze_with_sentillm(
        self,
        instruction: str,
        input_text: str,
        language: str,
        cve_id: str,
        dep_name: str,
        dep_version: str,
        dep_repo: str
    ) -> Dict:
        """SentiLLM ile CVE analizi"""
        try:
            # Prompt oluştur (Training format)
            prompt = self.ALPACA_PROMPT.format(
                scenario="vulnerability_analysis",
                language=language,
                expected_result="ANALYZE",  # Model kendi karar verecek
                instruction=instruction,
                input=input_text,
                output=""
            )
            
            # Tokenize
            inputs = self.sentillm_tokenizer(
                prompt, 
                return_tensors="pt"
            )
            
            # GPU/CPU device
            device = next(self.sentillm_model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}
            
            # Generate
            with torch.no_grad():
                outputs = self.sentillm_model.generate(
                    **inputs,
                    max_new_tokens=512,
                    temperature=0.1,
                    top_p=0.9,
                    do_sample=True,
                    pad_token_id=self.sentillm_tokenizer.eos_token_id,
                )
            
            # Decode
            response = self.sentillm_tokenizer.batch_decode(outputs)[0]
            
            # Response kısmını ayıkla
            response_start = response.find("### Response:") + len("### Response:")
            result_text = response[response_start:].strip()
            
            # EOS token temizle
            eos_token = self.sentillm_tokenizer.eos_token
            if eos_token:
                result_text = result_text.replace(eos_token, "")
            
            # JSON parse
            json_match = re.search(r'\{[^{}]*\}', result_text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                
                # Standart format
                return {
                    "vulnerable": analysis.get("vulnerable", analysis.get("is_vulnerable", False)),
                    "risk_level": self._map_severity(analysis.get("severity", analysis.get("risk_level", "N/A"))),
                    "reason": analysis.get("rationale", analysis.get("reason", "Analiz yapıldı")),
                    "recommended_version": analysis.get("safe_version", analysis.get("recommended_version")),
                    "action_required": analysis.get("action_required", analysis.get("fix_command", "Manuel inceleme")),
                    "cve_id": cve_id,
                    "dependency": dep_name,
                    "current_version": dep_version,
                    "repo": dep_repo,
                    "analyzed_by": "SentiLLM"
                }
            
            # JSON bulunamadı - text'ten parse et
            is_vulnerable = "VULNERABLE" in result_text.upper() and "NOT VULNERABLE" not in result_text.upper()
            
            return {
                "vulnerable": is_vulnerable,
                "risk_level": "YÜKSEK" if is_vulnerable else "YOK",
                "reason": result_text[:200],
                "recommended_version": None,
                "action_required": "Manuel inceleme gerekli",
                "cve_id": cve_id,
                "dependency": dep_name,
                "current_version": dep_version,
                "repo": dep_repo,
                "analyzed_by": "SentiLLM"
            }
            
        except Exception as e:
            print(f"⚠️ SentiLLM analiz hatası: {e}")
            return self._rule_based_analysis(
                {"cve_id": cve_id}, 
                {"name": dep_name, "version": dep_version, "repo": dep_repo}
            )
    
    def _analyze_with_openai(
        self,
        instruction: str,
        input_text: str,
        cve_id: str,
        dep_name: str,
        dep_version: str,
        dep_repo: str
    ) -> Dict:
        """OpenAI API ile fallback analiz"""
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Sen bir siber güvenlik uzmanısın. JSON formatında yanıt ver."},
                    {"role": "user", "content": f"{instruction}\n\n{input_text}"}
                ],
                temperature=0.1,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content
            
            json_match = re.search(r'\{[^{}]*\}', result_text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                analysis["cve_id"] = cve_id
                analysis["dependency"] = dep_name
                analysis["current_version"] = dep_version
                analysis["repo"] = dep_repo
                analysis["analyzed_by"] = "OpenAI"
                return analysis
                
        except Exception as e:
            print(f"⚠️ OpenAI analiz hatası: {e}")
        
        return self._rule_based_analysis(
            {"cve_id": cve_id}, 
            {"name": dep_name, "version": dep_version, "repo": dep_repo}
        )
    
    def _map_severity(self, severity: str) -> str:
        """Severity mapping (EN -> TR)"""
        mapping = {
            "CRITICAL": "KRİTİK",
            "HIGH": "YÜKSEK",
            "MEDIUM": "ORTA",
            "LOW": "DÜŞÜK",
            "NONE": "YOK"
        }
        return mapping.get(severity.upper(), severity) if severity else "N/A"
    
    def _rule_based_analysis(self, cve_data: Dict, matched_dependency: Dict) -> Dict:
        """LLM olmadan basit kural tabanlı analiz"""
        affected = cve_data.get("affected_software", [])
        dep_name = matched_dependency.get("name", "").lower()
        dep_version = matched_dependency.get("version", "")
        
        is_vulnerable = False
        
        for software in affected:
            software_lower = software.lower()
            if dep_name in software_lower:
                # Versiyon kontrolü
                version_match = re.search(r'[<>=]+\s*([\d.]+)', software)
                if version_match:
                    affected_version = version_match.group(1)
                    # Basit versiyon karşılaştırma
                    if "<" in software and dep_version:
                        try:
                            from packaging import version
                            if version.parse(dep_version) < version.parse(affected_version):
                                is_vulnerable = True
                        except:
                            is_vulnerable = True  # Emin değilsek tehlikeli say
                else:
                    is_vulnerable = True
        
        return {
            "vulnerable": is_vulnerable,
            "risk_level": "YÜKSEK" if is_vulnerable else "YOK",
            "reason": f"{dep_name} {dep_version} CVE'den etkileniyor olabilir" if is_vulnerable else "Eşleşme bulunamadı",
            "recommended_version": None,
            "action_required": "Manuel inceleme gerekli" if is_vulnerable else "Aksiyon gerekmiyor",
            "cve_id": cve_data.get("cve_id"),
            "dependency": dep_name,
            "current_version": dep_version,
            "repo": matched_dependency.get("repo")
        }
    
    def create_github_issue(
        self,
        repo_full_name: str,
        analysis: Dict,
        cve_data: Dict
    ) -> Optional[str]:
        """
        THE AGENT - ACTION 1: GitHub'da Issue aç
        """
        if not self.github:
            print("⚠️ GitHub client yok. Issue açılamadı.")
            return None
        
        try:
            repo = self.github.get_repo(repo_full_name)
            
            title = f"🚨 Güvenlik Açığı: {analysis.get('cve_id', 'Unknown CVE')} - {analysis.get('dependency', 'Unknown')}"
            
            body = f"""## 🔐 Güvenlik Açığı Tespit Edildi

**SentiLLM Otomatik Güvenlik Taraması** tarafından oluşturulmuştur.

---

### CVE Detayları
| Alan | Değer |
|------|-------|
| **CVE ID** | {analysis.get('cve_id', 'N/A')} |
| **CVSS Score** | {cve_data.get('cvss_score', 'N/A')} |
| **Severity** | {cve_data.get('severity', 'N/A')} |

### Etkilenen Bağımlılık
| Alan | Değer |
|------|-------|
| **Kütüphane** | `{analysis.get('dependency', 'N/A')}` |
| **Mevcut Versiyon** | `{analysis.get('current_version', 'N/A')}` |
| **Önerilen Versiyon** | `{analysis.get('recommended_version', 'Belirtilmedi')}` |

### Risk Analizi
- **Risk Seviyesi:** {analysis.get('risk_level', 'N/A')}
- **Açıklama:** {analysis.get('reason', 'N/A')}

### Önerilen Aksiyon
{analysis.get('action_required', 'Manuel inceleme gerekli')}

### CVE Açıklaması
> {cve_data.get('description', 'Açıklama bulunamadı')[:500]}...

---

📅 Tespit Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🤖 Bu issue SentiLLM tarafından otomatik oluşturulmuştur.
"""
            
            issue = repo.create_issue(
                title=title,
                body=body,
                labels=["security", "vulnerability", "automated"]
            )
            
            print(f"✅ Issue açıldı: {issue.html_url}")
            return issue.html_url
            
        except GithubException as e:
            print(f"⚠️ GitHub Issue hatası: {e}")
            return None
    
    def create_fix_pull_request(
        self,
        repo_full_name: str,
        analysis: Dict,
        dependency_file: str = "requirements.txt"
    ) -> Optional[str]:
        """
        THE AGENT - ACTION 2: Otomatik fix PR aç
        """
        if not self.github:
            print("⚠️ GitHub client yok. PR açılamadı.")
            return None
        
        if not analysis.get("recommended_version"):
            print("⚠️ Önerilen versiyon belirtilmemiş. PR açılamadı.")
            return None
        
        try:
            repo = self.github.get_repo(repo_full_name)
            
            # Mevcut dosyayı oku
            try:
                file = repo.get_contents(dependency_file)
                content = file.decoded_content.decode("utf-8")
            except:
                print(f"⚠️ {dependency_file} bulunamadı.")
                return None
            
            # Bağımlılığı güncelle
            dep_name = analysis.get("dependency", "")
            old_version = analysis.get("current_version", "")
            new_version = analysis.get("recommended_version", "")
            
            # Basit regex ile değiştir
            pattern = rf'({re.escape(dep_name)})==[\d.]+'
            replacement = f'{dep_name}=={new_version}'
            new_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
            
            if new_content == content:
                print("⚠️ Değişiklik yapılamadı.")
                return None
            
            # Yeni branch oluştur
            branch_name = f"security-fix/{analysis.get('cve_id', 'unknown').lower()}"
            
            # Default branch'i al
            default_branch = repo.default_branch
            source = repo.get_branch(default_branch)
            
            try:
                repo.create_git_ref(f"refs/heads/{branch_name}", source.commit.sha)
            except GithubException:
                # Branch zaten var
                pass
            
            # Dosyayı güncelle
            repo.update_file(
                path=dependency_file,
                message=f"🔒 Fix {analysis.get('cve_id')}: Update {dep_name} to {new_version}",
                content=new_content,
                sha=file.sha,
                branch=branch_name
            )
            
            # PR aç
            pr = repo.create_pull(
                title=f"🔒 Security Fix: {analysis.get('cve_id')} - Update {dep_name}",
                body=f"""## 🔐 Otomatik Güvenlik Güncellemesi

**SentiLLM** tarafından otomatik oluşturulmuştur.

### Değişiklikler
- `{dep_name}` kütüphanesi `{old_version}` → `{new_version}` olarak güncellendi

### CVE Detayları
- **CVE ID:** {analysis.get('cve_id')}
- **Risk Seviyesi:** {analysis.get('risk_level')}

### Neden?
{analysis.get('reason', 'Güvenlik açığı tespit edildi.')}

---
🤖 Bu PR SentiLLM tarafından otomatik oluşturulmuştur.
""",
                head=branch_name,
                base=default_branch
            )
            
            print(f"✅ PR açıldı: {pr.html_url}")
            return pr.html_url
            
        except GithubException as e:
            print(f"⚠️ GitHub PR hatası: {e}")
            return None
    
    def process_vulnerability(
        self,
        cve_data: Dict,
        matched_dependency: Dict,
        auto_fix: bool = False
    ) -> Dict:
        """
        Tam pipeline: Analiz et → Issue aç → (opsiyonel) PR aç
        """
        result = {
            "cve_id": cve_data.get("cve_id"),
            "dependency": matched_dependency.get("name"),
            "repo": matched_dependency.get("repo"),
            "analysis": None,
            "issue_url": None,
            "pr_url": None,
            "action_taken": []
        }
        
        # 1. Analiz
        print(f"\n🧠 Analiz ediliyor: {cve_data.get('cve_id')}...")
        analysis = self.analyze_vulnerability(cve_data, matched_dependency)
        result["analysis"] = analysis
        
        if not analysis.get("vulnerable"):
            print(f"✅ {cve_data.get('cve_id')} bu projeyi ETKİLEMİYOR.")
            result["action_taken"].append("Tehdit yok, aksiyon alınmadı")
            return result
        
        print(f"🚨 UYARI: {cve_data.get('cve_id')} bu projeyi ETKİLİYOR!")
        
        # 2. Issue aç
        repo = matched_dependency.get("repo")
        if repo and self.github:
            print(f"📝 Issue açılıyor: {repo}...")
            issue_url = self.create_github_issue(repo, analysis, cve_data)
            result["issue_url"] = issue_url
            if issue_url:
                result["action_taken"].append("Issue açıldı")
        
        # 3. Auto-fix PR (opsiyonel)
        if auto_fix and analysis.get("recommended_version"):
            print(f"🔧 Fix PR açılıyor...")
            pr_url = self.create_fix_pull_request(repo, analysis)
            result["pr_url"] = pr_url
            if pr_url:
                result["action_taken"].append("Fix PR açıldı")
        
        return result


# Test için
if __name__ == "__main__":
    import dotenv
    
    # API key'leri yükle
    github_token = dotenv.get_key(dotenv.find_dotenv(), "GITHUB_TOKEN")
    openai_key = dotenv.get_key(dotenv.find_dotenv(), "OPENAI_API_KEY")  # Fallback
    
    # ============================================================
    # SentiLLM Model Seçenekleri:
    # 1. HuggingFace'ten: "YOUR_USERNAME/sentillm-cve-analyzer-lora"
    # 2. Lokal path: "./sentillm-lora"
    # ============================================================
    
    SENTILLM_MODEL = "yoitsmeyusuf/sentillm-cve-analyzer-lora"  # ← HF model ID
    # SENTILLM_MODEL = "./sentillm-lora"  # ← veya lokal path
    
    agent = SecurityAgent(
        sentillm_model_path=SENTILLM_MODEL,
        github_token=github_token,
        openai_api_key=openai_key  # SentiLLM yoksa fallback
    )
    
    # Test verisi
    test_cve = {
        "cve_id": "CVE-2024-12345",
        "description": "Remote Code Execution vulnerability in requests library before 2.31.0",
        "affected_software": ["requests < 2.31.0"],
        "cvss_score": 9.8,
        "severity": "CRITICAL"
    }
    
    test_dep = {
        "name": "requests",
        "version": "2.28.1",
        "repo": "test-owner/test-repo",
        "file_type": "requirements.txt"
    }
    
    # Analiz
    print("\n" + "="*60)
    print("🧠 SentiLLM CVE Analizi")
    print("="*60)
    
    analysis = agent.analyze_vulnerability(test_cve, test_dep)
    print(json.dumps(analysis, indent=2, ensure_ascii=False))
    
    print("\n" + "="*60)
    if analysis.get("analyzed_by") == "SentiLLM":
        print("✅ Analiz: SentiLLM (Fine-tuned Llama-3-8B)")
    elif analysis.get("analyzed_by") == "OpenAI":
        print("⚠️ Analiz: OpenAI Fallback")
    else:
        print("⚠️ Analiz: Rule-based Fallback")
    print("="*60)
