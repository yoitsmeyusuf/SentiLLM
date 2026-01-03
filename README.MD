# 🛡️ SentiLLM - AI-Powered CVE Security Agent

Fine-tuned Llama-3-8B model ile otomatik güvenlik açığı analizi ve GitHub entegrasyonu.

## 🎯 Ne Yapar?

1. **CVE İzleme** - NVD API'den güncel güvenlik açıklarını çeker
2. **Repo Tarama** - GitHub repolarındaki bağımlılıkları analiz eder
3. **AI Analiz** - SentiLLM ile risk değerlendirmesi yapar
4. **Otomatik Issue** - Kritik açıklar için GitHub Issue oluşturur

## 🏗️ Mimari

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   NVD API   │────▶│  RAG Memory │────▶│  SentiLLM   │
│  (CVE Data) │     │  (ChromaDB) │     │  (Llama-3)  │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │   GitHub    │
                                        │   Issues    │
                                        └─────────────┘
```

## 🚀 Kurulum

```bash
git clone https://github.com/yoitsmeyusuf/SentiLLM.git
cd SentiLLM

# Python 3.12 önerilir
python -m venv .venv
.venv\Scripts\activate  # Windows

pip install -r requirements.txt

# GPU desteği (opsiyonel)
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

## ⚙️ Konfigürasyon

`.env` dosyası:
```env
GITHUB_TOKEN=ghp_xxxxxxxxxxxx
OPENAI_API_KEY=sk-xxxx  # Fallback (opsiyonel)
```

## 📦 Kullanım

```python
from modules.rag_memory import RAGMemory
from modules.ai_agent import SecurityAgent

# Repo tara
memory = RAGMemory()
result = memory.ingest_github_repo("https://github.com/user/repo", recursive=True)

# CVE analiz et
agent = SecurityAgent(sentillm_model_path="yoitsmeyusuf/sentillm-cve-analyzer-lora")
analysis = agent.analyze_vulnerability(cve_data, dependency)
```

## 🧪 Test

```bash
python test_pipeline.py        # Dry-run
python test_pipeline.py --live # Gerçek Issue oluştur
```

## 🤖 Model

| | |
|---|---|
| **Base** | meta-llama/Meta-Llama-3-8B |
| **Fine-tuned** | yoitsmeyusuf/sentillm-cve-analyzer-lora |
| **Method** | QLoRA (r=32) + NEFTune |

## 📁 Yapı

```
SentiLLM/
├── modules/
│   ├── ai_agent.py      # SentiLLM + GitHub Agent
│   └── rag_memory.py    # Repo tarama + ChromaDB
├── main.py              # NVD API entegrasyonu
├── test_pipeline.py     # E2E test
└── requirements.txt
```

## 📄 Lisans

MIT

---
*Built with 🦙 Llama-3 and ❤️*
