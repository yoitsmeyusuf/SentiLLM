SENTINLLM_PROJECT/
│
├── .env                  # API Key'ler burada
├── requirements.txt      # Kütüphaneler
├── main.py               # ORKESTRA ŞEFİ (Her şeyi burada birleştireceğiz)
│
├── modules/
│   ├── __init__.py
│   ├── cve_monitor.py    # (Yazdığın kod) NVD'yi dinleyen kulak
│   ├── rag_memory.py     # GitHub kodlarını vektöre çeviren hafıza
│   └── ai_agent.py       # (Şimdi yazacağımız) Karar veren beyin
│
└── data/                 # Geçici veriler (ChromaDB vb.)


1. Sistem Mimarisi (Architecture)

Akış Şeması:

    The Watchtower (Gözlemci): NIST NVD API'sini veya RSS feedlerini dinler. Yeni bir CVE düştüğü an yakalar.

    The Context (Vektör Hafıza): Kullanıcının GitHub reposunu (özellikle requirements.txt, pom.xml, package.json ve kritik fonksiyonları) okur ve vektör veritabanına gömer.

    The Brain (Analiz - RAG): Yeni gelen CVE ile projedeki kod parçalarını eşleştirir. LLM'e sorar: "Bu CVE bu projeyi vurur mu?"

    The Agent (Eylem): Eğer cevap "Evet" ise, GitHub API'sini kullanarak otomatik Issue veya Pull Request açar.

2. Teknoloji Yığını (Tech Stack)


    Backend: Python (FastAPI veya basit bir script).

    AI/LLM: Llama-3 (RunPod üzerinde) veya hızlı test için OpenAI API.

    Orchestration: LangChain (RAG ve Agent yapısı için standart, öğrenmesi kolay).

    Vector DB: ChromaDB

    External API:

        PyGithub (GitHub işlemleri için).

        NIST NVD API (CVE verileri için).