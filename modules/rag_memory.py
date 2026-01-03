"""
THE CONTEXT - RAG Memory Module
GitHub repolarını okur, bağımlılıkları çıkarır ve vektör veritabanına gömer.

Features:
- Recursive alt klasör tarama (monorepo desteği)
- Tüm hesabı/organization tarama
- Çoklu dil desteği (Python, Node.js, Java, Go, Rust, Ruby, PHP)
"""

import os
import re
import json
import requests
from typing import List, Dict, Optional, Tuple
from pathlib import Path

try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    print("⚠️ ChromaDB yüklü değil. 'pip install chromadb' ile yükleyin.")


class RAGMemory:
    """GitHub repolarını vektörize eden ve sorgulayan sınıf"""
    
    # Desteklenen bağımlılık dosyaları
    DEPENDENCY_FILES = {
        "requirements.txt": "python",
        "Pipfile": "python",
        "pyproject.toml": "python",
        "package.json": "nodejs",
        "package-lock.json": "nodejs",
        "pom.xml": "java",
        "build.gradle": "java",
        "Gemfile": "ruby",
        "go.mod": "go",
        "Cargo.toml": "rust",
        "composer.json": "php"
    }
    
    def __init__(self, db_path: str = "./data/chromadb"):
        self.db_path = db_path
        
        if CHROMADB_AVAILABLE:
            os.makedirs(db_path, exist_ok=True)
            self.client = chromadb.PersistentClient(path=db_path)
            self.collection = self.client.get_or_create_collection(
                name="dependencies",
                metadata={"description": "Project dependencies for vulnerability matching"}
            )
        else:
            self.client = None
            self.collection = None
            
        self.github_token: Optional[str] = None
        
    def set_github_token(self, token: str):
        """GitHub API token'ı ayarla"""
        self.github_token = token
        
    def _get_github_headers(self) -> Dict:
        """GitHub API için header'lar"""
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers
    
    def fetch_repo_contents(self, owner: str, repo: str, path: str = "") -> List[Dict]:
        """GitHub repo içeriğini çek"""
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = requests.get(url, headers=self._get_github_headers(), timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"⚠️ GitHub API hatası: {response.status_code}")
                return []
        except Exception as e:
            print(f"⚠️ Bağlantı hatası: {e}")
            return []
    
    def fetch_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        """GitHub'dan dosya içeriğini çek"""
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = requests.get(url, headers=self._get_github_headers(), timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get("encoding") == "base64":
                    import base64
                    return base64.b64decode(data["content"]).decode("utf-8")
                return data.get("content", "")
            return None
        except Exception as e:
            print(f"⚠️ Dosya okuma hatası: {e}")
            return None
    
    def parse_requirements_txt(self, content: str) -> List[Dict]:
        """requirements.txt dosyasını parse et"""
        dependencies = []
        
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            
            # Paket adı ve versiyon ayır
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!]+)?\s*([0-9.]+)?', line)
            if match:
                name = match.group(1).lower()
                operator = match.group(2) or "=="
                version = match.group(3) or "latest"
                
                dependencies.append({
                    "name": name,
                    "version": version,
                    "operator": operator,
                    "raw": line,
                    "ecosystem": "python"
                })
        
        return dependencies
    
    def parse_package_json(self, content: str) -> List[Dict]:
        """package.json dosyasını parse et"""
        dependencies = []
        
        try:
            data = json.loads(content)
            
            for dep_type in ["dependencies", "devDependencies"]:
                deps = data.get(dep_type, {})
                for name, version in deps.items():
                    # Versiyon temizle (^, ~, >= vb.)
                    clean_version = re.sub(r'^[\^~>=<]+', '', version)
                    
                    dependencies.append({
                        "name": name.lower(),
                        "version": clean_version,
                        "raw": f"{name}@{version}",
                        "ecosystem": "nodejs",
                        "dev": dep_type == "devDependencies"
                    })
        except json.JSONDecodeError:
            print("⚠️ package.json parse hatası")
        
        return dependencies
    
    def parse_pom_xml(self, content: str) -> List[Dict]:
        """pom.xml dosyasını parse et (basit regex)"""
        dependencies = []
        
        # Basit regex ile dependency'leri bul
        pattern = r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for group_id, artifact_id, version in matches:
            dependencies.append({
                "name": f"{group_id}:{artifact_id}".lower(),
                "version": version or "latest",
                "raw": f"{group_id}:{artifact_id}:{version}",
                "ecosystem": "java"
            })
        
        return dependencies
    
    def parse_pyproject_toml(self, content: str) -> List[Dict]:
        """pyproject.toml dosyasını parse et (PEP 621 formatı)"""
        dependencies = []
        
        # [project] dependencies bölümünü bul
        # Format: dependencies = ["flask>=2.0", "requests>=2.28,<3.0"]
        dep_pattern = r'\[project\].*?dependencies\s*=\s*\[(.*?)\]'
        match = re.search(dep_pattern, content, re.DOTALL)
        
        if match:
            deps_block = match.group(1)
            # Her dependency satırını parse et
            dep_lines = re.findall(r'"([^"]+)"', deps_block)
            
            for dep in dep_lines:
                # Paket adı ve versiyon ayır
                # Örnekler: "flask>=2.0", "requests>=2.28,<3.0", "click"
                pkg_match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!,.\d\s]*)?', dep.strip())
                if pkg_match:
                    name = pkg_match.group(1).lower()
                    version_spec = pkg_match.group(2) or ""
                    
                    # İlk versiyon numarasını çıkar
                    version_num = re.search(r'[\d.]+', version_spec)
                    version = version_num.group() if version_num else "latest"
                    
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "raw": dep,
                        "ecosystem": "python"
                    })
        
        # [project.optional-dependencies] bölümünü de tara
        opt_pattern = r'\[project\.optional-dependencies\](.*?)(?=\[|$)'
        opt_match = re.search(opt_pattern, content, re.DOTALL)
        
        if opt_match:
            opt_block = opt_match.group(1)
            dep_lines = re.findall(r'"([^"]+)"', opt_block)
            
            for dep in dep_lines:
                pkg_match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!,.\d\s]*)?', dep.strip())
                if pkg_match:
                    name = pkg_match.group(1).lower()
                    version_spec = pkg_match.group(2) or ""
                    version_num = re.search(r'[\d.]+', version_spec)
                    version = version_num.group() if version_num else "latest"
                    
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "raw": dep,
                        "ecosystem": "python",
                        "optional": True
                    })
        
        return dependencies
    
    def parse_dependency_file(self, filename: str, content: str) -> List[Dict]:
        """Bağımlılık dosyasını parse et"""
        if filename == "requirements.txt":
            return self.parse_requirements_txt(content)
        elif filename == "package.json":
            return self.parse_package_json(content)
        elif filename == "pom.xml":
            return self.parse_pom_xml(content)
        elif filename == "pyproject.toml":
            return self.parse_pyproject_toml(content)
        # Diğer formatlar için genişletilebilir
        return []
    
    def _scan_directory_recursive(
        self, 
        owner: str, 
        repo: str, 
        path: str = "",
        max_depth: int = 5,
        current_depth: int = 0
    ) -> List[Dict]:
        """
        Recursive olarak dizin tara ve dependency dosyalarını bul
        Monorepo desteği için alt klasörlere de bakar
        """
        if current_depth >= max_depth:
            return []
        
        found_deps = []
        contents = self.fetch_repo_contents(owner, repo, path)
        
        for item in contents:
            item_path = f"{path}/{item['name']}" if path else item["name"]
            
            if item["type"] == "file" and item["name"] in self.DEPENDENCY_FILES:
                # Dependency dosyası bulundu
                print(f"  📄 Bulundu: {item_path}")
                content = self.fetch_file_content(owner, repo, item_path)
                if content:
                    deps = self.parse_dependency_file(item["name"], content)
                    for dep in deps:
                        dep["source_file"] = item_path
                        dep["repo"] = f"{owner}/{repo}"
                    found_deps.extend(deps)
            
            elif item["type"] == "dir":
                # Skip common non-relevant directories
                skip_dirs = {
                    "node_modules", ".git", "__pycache__", ".venv", "venv",
                    "dist", "build", ".next", ".nuxt", "vendor", "target",
                    ".idea", ".vscode", "coverage", ".pytest_cache"
                }
                if item["name"] not in skip_dirs:
                    # Recursive olarak alt dizini tara
                    found_deps.extend(
                        self._scan_directory_recursive(
                            owner, repo, item_path, max_depth, current_depth + 1
                        )
                    )
        
        return found_deps
    
    def ingest_github_repo(
        self, 
        repo_url: str,
        recursive: bool = True,
        max_depth: int = 5
    ) -> Dict:
        """
        GitHub reposunu analiz et ve vektör veritabanına kaydet
        
        Args:
            repo_url: https://github.com/owner/repo formatında
            recursive: Alt klasörleri de tara (monorepo desteği)
            max_depth: Maksimum alt klasör derinliği (default: 5)
        """
        # URL'den owner ve repo çıkar
        match = re.match(r'https?://github\.com/([^/]+)/([^/]+)/?', repo_url)
        if not match:
            return {"error": "Geçersiz GitHub URL"}
        
        owner, repo = match.groups()
        repo = repo.rstrip('.git')
        
        print(f"📥 Repo analiz ediliyor: {owner}/{repo}")
        print(f"   Recursive: {recursive}, Max depth: {max_depth}")
        
        if recursive:
            # Recursive tarama
            all_dependencies = self._scan_directory_recursive(owner, repo, "", max_depth, 0)
            found_files = list(set(dep.get("source_file", "") for dep in all_dependencies))
        else:
            # Sadece root dizin
            contents = self.fetch_repo_contents(owner, repo)
            all_dependencies = []
            found_files = []
            
            for item in contents:
                if item["type"] == "file" and item["name"] in self.DEPENDENCY_FILES:
                    print(f"  📄 Bulundu: {item['name']}")
                    found_files.append(item["name"])
                    
                    content = self.fetch_file_content(owner, repo, item["name"])
                    if content:
                        deps = self.parse_dependency_file(item["name"], content)
                        for dep in deps:
                            dep["source_file"] = item["name"]
                            dep["repo"] = f"{owner}/{repo}"
                        all_dependencies.extend(deps)
        
        # Vektör veritabanına kaydet
        if CHROMADB_AVAILABLE and self.collection and all_dependencies:
            self._store_in_chromadb(all_dependencies, f"{owner}/{repo}")
        
        result = {
            "repo": f"{owner}/{repo}",
            "files_found": found_files,
            "total_dependencies": len(all_dependencies),
            "dependencies": all_dependencies,
            "recursive": recursive
        }
        
        print(f"✅ {len(all_dependencies)} bağımlılık bulundu ({len(found_files)} dosyada)")
        return result
    
    # ================================================================
    # HESAP/ORGANIZATION TARAMA
    # ================================================================
    
    def fetch_user_repos(self, username: str, include_forks: bool = False) -> List[Dict]:
        """Kullanıcının tüm public repolarını getir"""
        repos = []
        page = 1
        per_page = 100
        
        while True:
            url = f"https://api.github.com/users/{username}/repos?page={page}&per_page={per_page}&type=owner"
            
            try:
                response = requests.get(url, headers=self._get_github_headers(), timeout=30)
                if response.status_code != 200:
                    print(f"⚠️ GitHub API hatası: {response.status_code}")
                    break
                
                data = response.json()
                if not data:
                    break
                
                for repo in data:
                    if not include_forks and repo.get("fork"):
                        continue
                    repos.append({
                        "name": repo["name"],
                        "full_name": repo["full_name"],
                        "url": repo["html_url"],
                        "language": repo.get("language"),
                        "stars": repo.get("stargazers_count", 0),
                        "updated_at": repo.get("updated_at")
                    })
                
                page += 1
                
            except Exception as e:
                print(f"⚠️ Bağlantı hatası: {e}")
                break
        
        return repos
    
    def fetch_org_repos(self, org: str, include_forks: bool = False) -> List[Dict]:
        """Organization'ın tüm public repolarını getir"""
        repos = []
        page = 1
        per_page = 100
        
        while True:
            url = f"https://api.github.com/orgs/{org}/repos?page={page}&per_page={per_page}&type=all"
            
            try:
                response = requests.get(url, headers=self._get_github_headers(), timeout=30)
                if response.status_code != 200:
                    print(f"⚠️ GitHub API hatası: {response.status_code}")
                    break
                
                data = response.json()
                if not data:
                    break
                
                for repo in data:
                    if not include_forks and repo.get("fork"):
                        continue
                    repos.append({
                        "name": repo["name"],
                        "full_name": repo["full_name"],
                        "url": repo["html_url"],
                        "language": repo.get("language"),
                        "stars": repo.get("stargazers_count", 0),
                        "updated_at": repo.get("updated_at")
                    })
                
                page += 1
                
            except Exception as e:
                print(f"⚠️ Bağlantı hatası: {e}")
                break
        
        return repos
    
    def scan_account(
        self,
        username: str,
        scan_type: str = "user",  # "user" veya "org"
        include_forks: bool = False,
        recursive: bool = True,
        max_depth: int = 3,
        language_filter: Optional[List[str]] = None  # ["Python", "JavaScript"] gibi
    ) -> Dict:
        """
        Tüm hesabı veya organization'ı tara
        
        Args:
            username: GitHub kullanıcı adı veya organization adı
            scan_type: "user" veya "org"
            include_forks: Fork'ları dahil et
            recursive: Alt klasörleri tara
            max_depth: Maksimum derinlik
            language_filter: Sadece belirli dillerdeki repoları tara
        
        Returns:
            Tüm repolardan bulunan bağımlılıkların özeti
        """
        print(f"\n{'='*60}")
        print(f"🔍 HESAP TARAMASI: {username} ({scan_type})")
        print(f"{'='*60}")
        print(f"   Include forks: {include_forks}")
        print(f"   Recursive: {recursive}")
        print(f"   Language filter: {language_filter or 'All'}")
        print(f"{'='*60}\n")
        
        # Repoları getir
        if scan_type == "org":
            repos = self.fetch_org_repos(username, include_forks)
        else:
            repos = self.fetch_user_repos(username, include_forks)
        
        print(f"📦 Toplam {len(repos)} repo bulundu")
        
        # Language filter uygula
        if language_filter:
            language_filter_lower = [l.lower() for l in language_filter]
            repos = [r for r in repos if r.get("language") and r["language"].lower() in language_filter_lower]
            print(f"   {len(repos)} repo filter sonrası kaldı")
        
        all_results = []
        total_deps = 0
        scanned_repos = 0
        
        for i, repo in enumerate(repos, 1):
            print(f"\n[{i}/{len(repos)}] 📥 {repo['full_name']}...")
            
            try:
                result = self.ingest_github_repo(
                    repo["url"],
                    recursive=recursive,
                    max_depth=max_depth
                )
                
                if result.get("total_dependencies", 0) > 0:
                    all_results.append(result)
                    total_deps += result["total_dependencies"]
                    scanned_repos += 1
                    
            except Exception as e:
                print(f"   ⚠️ Hata: {e}")
        
        summary = {
            "account": username,
            "type": scan_type,
            "total_repos": len(repos),
            "scanned_repos": scanned_repos,
            "total_dependencies": total_deps,
            "results": all_results
        }
        
        print(f"\n{'='*60}")
        print(f"✅ TARAMA TAMAMLANDI")
        print(f"{'='*60}")
        print(f"   Taranan repo: {scanned_repos}/{len(repos)}")
        print(f"   Toplam bağımlılık: {total_deps}")
        print(f"{'='*60}")
        
        return summary        
   
    
    def _store_in_chromadb(self, dependencies: List[Dict], repo: str):
        """Bağımlılıkları ChromaDB'ye kaydet"""
        if not self.collection:
            return
        
        documents = []
        metadatas = []
        ids = []
        
        for i, dep in enumerate(dependencies):
            doc = f"{dep['name']} {dep['version']} {dep.get('ecosystem', '')}"
            documents.append(doc)
            metadatas.append({
                "name": dep["name"],
                "version": dep["version"],
                "ecosystem": dep.get("ecosystem", "unknown"),
                "repo": repo,
                "raw": dep.get("raw", "")
            })
            ids.append(f"{repo}_{dep['name']}_{i}")
        
        try:
            self.collection.upsert(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
        except Exception as e:
            print(f"⚠️ ChromaDB kayıt hatası: {e}")
    
    def search_dependency(self, query: str, n_results: int = 5) -> List[Dict]:
        """Bağımlılık ara (CVE ile eşleştirme için)"""
        if not CHROMADB_AVAILABLE or not self.collection:
            return []
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            matches = []
            if results and results["metadatas"]:
                for i, metadata in enumerate(results["metadatas"][0]):
                    matches.append({
                        **metadata,
                        "distance": results["distances"][0][i] if results.get("distances") else None
                    })
            
            return matches
        except Exception as e:
            print(f"⚠️ Arama hatası: {e}")
            return []
    
    def match_cve_with_dependencies(self, cve_data: Dict) -> List[Dict]:
        """CVE'yi projedeki bağımlılıklarla eşleştir"""
        matches = []
        
        affected_software = cve_data.get("affected_software", [])
        
        for software in affected_software:
            # Software adını temizle
            software_name = software.split()[0].lower() if software else ""
            
            if software_name and software_name != "not":
                search_results = self.search_dependency(software_name)
                
                for result in search_results:
                    if software_name in result.get("name", "").lower():
                        matches.append({
                            "cve_id": cve_data.get("cve_id"),
                            "affected_software": software,
                            "matched_dependency": result
                        })
        
        return matches
    
    def get_all_dependencies(self) -> List[Dict]:
        """Tüm kayıtlı bağımlılıkları getir"""
        if not CHROMADB_AVAILABLE or not self.collection:
            return []
        
        try:
            results = self.collection.get()
            deps = []
            if results and results["metadatas"]:
                for metadata in results["metadatas"]:
                    deps.append(metadata)
            return deps
        except Exception as e:
            print(f"⚠️ Veri çekme hatası: {e}")
            return []


# Test için
if __name__ == "__main__":
    import dotenv
    
    memory = RAGMemory()
    
    # GitHub token varsa ayarla
    token = dotenv.get_key(dotenv.find_dotenv(), "GITHUB_TOKEN")
    if token:
        memory.set_github_token(token)
    
    print("="*60)
    print("🧪 RAG MEMORY TEST")
    print("="*60)
    
    # ================================================================
    # TEST 1: Tek repo tarama (recursive)
    # ================================================================
    # print("\n📦 TEST 1: Tek repo tarama (recursive)")
    # result = memory.ingest_github_repo(
    #     "https://github.com/pallets/flask",
    #     recursive=True,
    #     max_depth=3
    # )
    # print(f"   Bulunan bağımlılık: {result.get('total_dependencies', 0)}")
    
    # ================================================================
    # TEST 2: Tek repo tarama (sadece root)
    # ================================================================
    # print("\n📦 TEST 2: Tek repo tarama (sadece root)")
    # result = memory.ingest_github_repo(
    #     "https://github.com/pallets/flask",
    #     recursive=False
    # )
    # print(f"   Bulunan bağımlılık: {result.get('total_dependencies', 0)}")
    
    # ================================================================
    # TEST 3: Tüm hesabı tarama (uncomment to test)
    # ================================================================
    # print("\n📦 TEST 3: Tüm hesabı tarama")
    result = memory.scan_account(
        username="yoitsmeyusuf",  # GitHub kullanıcı adı
        scan_type="user",          # "user" veya "org"
        include_forks=False,       # Fork'ları dahil etme
        recursive=True,            # Alt klasörleri tara
        max_depth=3,               # Maksimum derinlik
        language_filter=None       # Tüm dilleri tara
    )
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))