"""
SENTILLM - Synthetic Training Data Generator v2.0
Knowledge Distillation için GPT-4 formatında eğitim verisi üretir.

Scenario Distribution:
- 40%: Vulnerable (Version is older than fixed version)
- 30%: Safe (Version is newer - False Positive training)
- 20%: Not Found (Library not in dependency file)
- 10%: Complex Ranges (e.g., '>1.0.0, <1.5.2')

Output Format: JSON Array with instruction, input, output
"""

import json
import random
import os
from typing import List, Dict, Optional
from datetime import datetime
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

# Get OpenAI API key from environment
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# ==================== REALISTIC PACKAGE DATA ====================

PYTHON_PACKAGES = [
    {"name": "django", "versions": ["2.2.0", "2.2.10", "3.0.0", "3.1.0", "3.2.5", "3.2.10", "4.0.0", "4.1.0", "4.2.0", "5.0.0"]},
    {"name": "flask", "versions": ["1.0.0", "1.1.0", "1.1.4", "2.0.0", "2.1.0", "2.2.0", "2.3.0", "3.0.0"]},
    {"name": "requests", "versions": ["2.20.0", "2.25.0", "2.26.0", "2.28.0", "2.28.1", "2.31.0", "2.32.0"]},
    {"name": "sqlalchemy", "versions": ["1.2.0", "1.3.5", "1.4.0", "1.4.20", "1.4.45", "2.0.0", "2.0.20"]},
    {"name": "pillow", "versions": ["8.0.0", "8.3.0", "9.0.0", "9.3.0", "9.5.0", "10.0.0", "10.1.0"]},
    {"name": "numpy", "versions": ["1.19.0", "1.20.0", "1.21.0", "1.22.0", "1.23.0", "1.24.0", "1.26.0"]},
    {"name": "pandas", "versions": ["1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.5.3", "2.0.0", "2.1.0"]},
    {"name": "cryptography", "versions": ["3.0", "3.4", "38.0.0", "39.0.0", "40.0.0", "41.0.0", "42.0.0"]},
    {"name": "pyyaml", "versions": ["5.1", "5.3", "5.4", "5.4.1", "6.0", "6.0.1"]},
    {"name": "jinja2", "versions": ["2.10", "2.11", "2.11.3", "3.0.0", "3.1.0", "3.1.2", "3.1.3"]},
    {"name": "urllib3", "versions": ["1.24.0", "1.25.0", "1.26.0", "1.26.15", "2.0.0", "2.1.0"]},
    {"name": "werkzeug", "versions": ["1.0.0", "1.0.1", "2.0.0", "2.1.0", "2.2.0", "2.3.0", "3.0.0"]},
    {"name": "fastapi", "versions": ["0.70.0", "0.80.0", "0.90.0", "0.95.0", "0.100.0", "0.109.0"]},
    {"name": "pydantic", "versions": ["1.8.0", "1.9.0", "1.10.0", "1.10.12", "2.0.0", "2.5.0"]},
    {"name": "aiohttp", "versions": ["3.6.0", "3.7.0", "3.8.0", "3.8.5", "3.9.0"]},
    {"name": "httpx", "versions": ["0.20.0", "0.23.0", "0.24.0", "0.25.0", "0.26.0"]},
    {"name": "celery", "versions": ["4.4.0", "5.0.0", "5.2.0", "5.3.0", "5.4.0"]},
    {"name": "redis", "versions": ["3.5.0", "4.0.0", "4.5.0", "5.0.0"]},
    {"name": "boto3", "versions": ["1.20.0", "1.26.0", "1.28.0", "1.34.0"]},
    {"name": "tensorflow", "versions": ["2.8.0", "2.10.0", "2.12.0", "2.14.0", "2.15.0"]},
    {"name": "pytorch", "versions": ["1.10.0", "1.12.0", "2.0.0", "2.1.0", "2.2.0"]},
    {"name": "scikit-learn", "versions": ["0.24.0", "1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]},
]

NODE_PACKAGES = [
    {"name": "express", "versions": ["4.16.0", "4.17.0", "4.17.3", "4.18.0", "4.18.2", "4.19.0"]},
    {"name": "lodash", "versions": ["4.17.10", "4.17.15", "4.17.19", "4.17.20", "4.17.21"]},
    {"name": "axios", "versions": ["0.21.0", "0.21.4", "0.27.0", "1.0.0", "1.4.0", "1.6.0"]},
    {"name": "jsonwebtoken", "versions": ["8.0.0", "8.5.0", "8.5.1", "9.0.0", "9.0.2"]},
    {"name": "mongoose", "versions": ["5.0.0", "5.13.0", "6.0.0", "7.0.0", "8.0.0"]},
    {"name": "next", "versions": ["12.0.0", "12.3.0", "13.0.0", "13.5.0", "14.0.0", "14.1.0"]},
    {"name": "react", "versions": ["17.0.0", "17.0.2", "18.0.0", "18.2.0"]},
    {"name": "socket.io", "versions": ["3.0.0", "4.0.0", "4.5.0", "4.6.0"]},
    {"name": "passport", "versions": ["0.5.0", "0.6.0", "0.7.0"]},
    {"name": "bcrypt", "versions": ["5.0.0", "5.0.1", "5.1.0", "5.1.1"]},
    {"name": "dotenv", "versions": ["10.0.0", "14.0.0", "16.0.0", "16.3.0"]},
    {"name": "helmet", "versions": ["4.0.0", "5.0.0", "6.0.0", "7.0.0", "7.1.0"]},
]

# Vulnerability Types with Descriptions
VULNERABILITY_TYPES = [
    {"type": "Remote Code Execution (RCE)", "desc": "allows attackers to execute arbitrary code on the target system"},
    {"type": "SQL Injection", "desc": "enables attackers to inject malicious SQL queries to access or modify database records"},
    {"type": "Cross-Site Scripting (XSS)", "desc": "allows injection of malicious scripts into web pages viewed by other users"},
    {"type": "Denial of Service (DoS)", "desc": "can cause the application to crash or become unresponsive when processing malformed input"},
    {"type": "Path Traversal", "desc": "allows attackers to access files outside the intended directory structure"},
    {"type": "Authentication Bypass", "desc": "enables unauthorized access by circumventing authentication mechanisms"},
    {"type": "Information Disclosure", "desc": "exposes sensitive information including credentials or internal system details"},
    {"type": "Server-Side Request Forgery (SSRF)", "desc": "allows attackers to make requests from the server to internal resources"},
    {"type": "Deserialization Vulnerability", "desc": "allows execution of arbitrary code via malicious serialized objects"},
    {"type": "Prototype Pollution", "desc": "enables modification of JavaScript object prototypes leading to potential RCE"},
    {"type": "Command Injection", "desc": "allows execution of arbitrary system commands on the host operating system"},
    {"type": "XML External Entity (XXE)", "desc": "allows reading local files or making network requests via malicious XML"},
    {"type": "Memory Corruption", "desc": "can lead to crashes or arbitrary code execution through buffer manipulation"},
    {"type": "Privilege Escalation", "desc": "allows attackers to gain elevated permissions beyond their authorization"},
]

# Comments for noise
PYTHON_COMMENTS = [
    "# Legacy code, do not touch",
    "# TODO: Update this dependency",
    "# FIXME: Known security issue",
    "# Production dependencies",
    "# Development only",
    "# Data processing libs",
    "# Networking utilities",
    "# Auth & Security",
    "# Database connectors",
    "# API framework",
    "# Testing tools",
    "# Deprecated - remove in next sprint",
    "# Required by legacy module",
    "# Pinned version for compatibility",
    "# Core dependencies",
]

NODE_COMMENTS = [
    "// Legacy dependency",
    "// TODO: Upgrade ASAP",
    "// Required for backwards compat",
    "// Production only",
    "// Development utilities",
]

# Standard instruction prompt
INSTRUCTION_PROMPT = """You are a Senior Product Security Engineer. Analyze the provided 'CVE Intelligence Report' and the 'Dependency File'. 
1. Determine if the project is vulnerable based on Semantic Versioning rules.
2. Ignore comments and unrelated libraries in the file.
3. Provide a strictly valid JSON response containing the risk assessment, reasoning, and remediation command."""


class SyntheticDataGenerator:
    """Generates synthetic training data for CVE analysis"""
    
    def __init__(self, openai_api_key: Optional[str] = None, use_gpt: bool = False):
        self.use_gpt = use_gpt and OPENAI_AVAILABLE and openai_api_key
        
        if self.use_gpt:
            self.client = OpenAI(api_key=openai_api_key)
        else:
            self.client = None
            
        self.generated_data: List[Dict] = []
        
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Semantic versioning comparison
        Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        def normalize(v):
            parts = []
            for x in v.replace("-", ".").split(".")[:3]:
                if x.isdigit():
                    parts.append(int(x))
            return parts
        
        n1, n2 = normalize(v1), normalize(v2)
        
        while len(n1) < 3:
            n1.append(0)
        while len(n2) < 3:
            n2.append(0)
        
        for a, b in zip(n1, n2):
            if a < b:
                return -1
            elif a > b:
                return 1
        return 0
    
    def _generate_cve_id(self) -> str:
        """Generate random CVE ID"""
        year = random.choice(["2023", "2024", "2025"])
        num = random.randint(1000, 99999)
        return f"CVE-{year}-{num}"
    
    def _get_severity(self, cvss: float) -> str:
        """Get severity label from CVSS score"""
        if cvss >= 9.0:
            return "CRITICAL"
        elif cvss >= 7.0:
            return "HIGH"
        elif cvss >= 4.0:
            return "MEDIUM"
        elif cvss > 0:
            return "LOW"
        return "NONE"
    
    def _generate_cvss_score(self, severity: Optional[str] = None) -> float:
        """Generate CVSS score"""
        if severity == "CRITICAL":
            return round(random.uniform(9.0, 10.0), 1)
        elif severity == "HIGH":
            return round(random.uniform(7.0, 8.9), 1)
        elif severity == "MEDIUM":
            return round(random.uniform(4.0, 6.9), 1)
        elif severity == "LOW":
            return round(random.uniform(0.1, 3.9), 1)
        return round(random.uniform(4.0, 10.0), 1)
    
    def _generate_noisy_requirements(self, 
                                     target_pkg: Optional[str] = None, 
                                     target_version: Optional[str] = None,
                                     include_target: bool = True,
                                     lang: str = "python") -> str:
        """Generate a realistic, noisy dependency file"""
        
        if lang == "python":
            packages = PYTHON_PACKAGES
            comments = PYTHON_COMMENTS
        else:
            packages = NODE_PACKAGES
            comments = NODE_COMMENTS
        
        lines = []
        
        # Add header comment
        lines.append(random.choice([
            "# Project Dependencies",
            "# requirements.txt - Auto-generated",
            "# Core project dependencies",
            "# === Production Dependencies ===",
        ]))
        lines.append("")
        
        # Add random section with comment
        lines.append(random.choice(comments))
        
        # Add 3-6 unrelated packages
        unrelated_count = random.randint(3, 6)
        available_packages = [p for p in packages if p["name"] != target_pkg]
        selected_packages = random.sample(available_packages, min(unrelated_count, len(available_packages)))
        
        for pkg in selected_packages:
            version = random.choice(pkg["versions"])
            
            # Add random formatting variations
            format_choice = random.choice([
                f"{pkg['name']}=={version}",
                f"{pkg['name']}=={version}  {random.choice(comments)}",
                f"{pkg['name']}>={version}",
            ])
            lines.append(format_choice)
            
            # Random blank line
            if random.random() > 0.7:
                lines.append("")
        
        # Add another section comment
        lines.append("")
        lines.append(random.choice(comments))
        
        # Add target package if required
        if include_target and target_pkg and target_version:
            target_line = f"{target_pkg}=={target_version}"
            
            # Add inline comment sometimes
            if random.random() > 0.5:
                target_line += f"  {random.choice(comments)}"
            
            # Insert at random position in the middle
            insert_pos = random.randint(len(lines) // 2, len(lines))
            lines.insert(insert_pos, target_line)
        
        # Add more unrelated packages after
        for _ in range(random.randint(1, 3)):
            pkg = random.choice(available_packages)
            version = random.choice(pkg["versions"])
            lines.append(f"{pkg['name']}=={version}")
        
        # Add trailing blank line
        lines.append("")
        
        return "\n".join(lines)
    
    def _generate_noisy_package_json(self,
                                     target_pkg: Optional[str] = None,
                                     target_version: Optional[str] = None,
                                     include_target: bool = True) -> str:
        """Generate a realistic, noisy package.json"""
        
        dependencies = {}
        dev_dependencies = {}
        
        # Add 3-5 unrelated packages
        available_packages = [p for p in NODE_PACKAGES if p["name"] != target_pkg]
        selected = random.sample(available_packages, min(5, len(available_packages)))
        
        for pkg in selected:
            version = random.choice(pkg["versions"])
            prefix = random.choice(["^", "~", ""])
            
            if random.random() > 0.3:
                dependencies[pkg["name"]] = f"{prefix}{version}"
            else:
                dev_dependencies[pkg["name"]] = f"{prefix}{version}"
        
        # Add target package
        if include_target and target_pkg and target_version:
            prefix = random.choice(["^", "~", ""])
            dependencies[target_pkg] = f"{prefix}{target_version}"
        
        package_json = {
            "name": f"example-project-{random.randint(100, 999)}",
            "version": "1.0.0",
            "description": "A sample project for security analysis",
            "dependencies": dependencies
        }
        
        if dev_dependencies:
            package_json["devDependencies"] = dev_dependencies
        
        # Format with comments (JSON5-style comments for training)
        json_str = json.dumps(package_json, indent=2)
        
        # Add comment-like lines (models should learn to handle this)
        if random.random() > 0.5:
            lines = json_str.split("\n")
            insert_pos = random.randint(2, len(lines) - 2)
            lines.insert(insert_pos, '  // TODO: Review these dependencies')
            json_str = "\n".join(lines)
        
        return json_str
    
    def _generate_cve_report(self, 
                             cve_id: str,
                             pkg_name: str,
                             safe_version: str,
                             vuln_type: Dict,
                             cvss: float,
                             severity: str,
                             affected_range: Optional[str] = None) -> str:
        """Generate a CVE intelligence report"""
        
        if affected_range is None:
            affected_range = f"{pkg_name} < {safe_version}"
        
        report = f"""--- CVE INTELLIGENCE REPORT ---
CVE ID: {cve_id}
Title: {vuln_type['type']} in '{pkg_name}' library
Severity: {severity} (CVSS {cvss})
Affected Versions: {affected_range}
Description: A vulnerability in the '{pkg_name}' library {vuln_type['desc']}. All users running affected versions should upgrade immediately to mitigate potential attacks."""
        
        return report
    
    # ==================== SCENARIO GENERATORS ====================
    
    def generate_vulnerable(self) -> Dict:
        """40% - Generate a VULNERABLE scenario"""
        lang = random.choice(["python", "nodejs"])
        
        if lang == "python":
            packages = PYTHON_PACKAGES
            file_type = "requirements.txt"
            cmd_prefix = "pip install"
        else:
            packages = NODE_PACKAGES
            file_type = "package.json"
            cmd_prefix = "npm install"
        
        # Select package with enough versions
        pkg = random.choice([p for p in packages if len(p["versions"]) >= 4])
        pkg_name = pkg["name"]
        versions = pkg["versions"]
        
        # Safe version is somewhere in the middle-upper range
        safe_idx = random.randint(len(versions) // 2, len(versions) - 1)
        safe_version = versions[safe_idx]
        
        # Project uses an OLDER (vulnerable) version
        vuln_idx = random.randint(0, safe_idx - 1)
        project_version = versions[vuln_idx]
        
        # CVE details
        vuln_type = random.choice(VULNERABILITY_TYPES)
        cve_id = self._generate_cve_id()
        severity = random.choice(["CRITICAL", "HIGH", "MEDIUM"])
        cvss = self._generate_cvss_score(severity)
        
        # Generate noisy dependency file
        if lang == "python":
            dep_file = self._generate_noisy_requirements(pkg_name, project_version, True, "python")
        else:
            dep_file = self._generate_noisy_package_json(pkg_name, project_version, True)
        
        # Generate CVE report
        cve_report = self._generate_cve_report(cve_id, pkg_name, safe_version, vuln_type, cvss, severity)
        
        # Construct input
        input_text = f"""{cve_report}

--- TARGET DEPENDENCY FILE ({file_type}) ---
{dep_file}"""
        
        # Construct output
        output = {
            "vulnerable": True,
            "severity": severity,
            "package": pkg_name,
            "current_version": project_version,
            "safe_version": f">={safe_version}",
            "rationale": f"The project uses '{pkg_name}' version '{project_version}'. The CVE report indicates that all versions strictly less than '{safe_version}' are vulnerable to {vuln_type['type']}. Since {project_version} < {safe_version}, the project is exposed to {severity.lower()} risk.",
            "fix_command": f"{cmd_prefix} {pkg_name}>={safe_version}",
            "action_required": "IMMEDIATE_UPDATE" if severity in ["CRITICAL", "HIGH"] else "SCHEDULED_UPDATE"
        }
        
        return {
            "instruction": INSTRUCTION_PROMPT,
            "input": input_text,
            "output": json.dumps(output, indent=2, ensure_ascii=False),
            "scenario": "vulnerable",
            "language": lang
        }
    
    def generate_safe(self) -> Dict:
        """30% - Generate a SAFE (False Positive) scenario"""
        lang = random.choice(["python", "nodejs"])
        
        if lang == "python":
            packages = PYTHON_PACKAGES
            file_type = "requirements.txt"
            cmd_prefix = "pip install"
        else:
            packages = NODE_PACKAGES
            file_type = "package.json"
            cmd_prefix = "npm install"
        
        pkg = random.choice([p for p in packages if len(p["versions"]) >= 4])
        pkg_name = pkg["name"]
        versions = pkg["versions"]
        
        # Safe version is in the lower-middle range
        safe_idx = random.randint(1, len(versions) // 2)
        safe_version = versions[safe_idx]
        
        # Project uses a NEWER (safe) version
        project_idx = random.randint(safe_idx, len(versions) - 1)
        project_version = versions[project_idx]
        
        vuln_type = random.choice(VULNERABILITY_TYPES)
        cve_id = self._generate_cve_id()
        severity = random.choice(["CRITICAL", "HIGH", "MEDIUM"])
        cvss = self._generate_cvss_score(severity)
        
        if lang == "python":
            dep_file = self._generate_noisy_requirements(pkg_name, project_version, True, "python")
        else:
            dep_file = self._generate_noisy_package_json(pkg_name, project_version, True)
        
        cve_report = self._generate_cve_report(cve_id, pkg_name, safe_version, vuln_type, cvss, severity)
        
        input_text = f"""{cve_report}

--- TARGET DEPENDENCY FILE ({file_type}) ---
{dep_file}"""
        
        output = {
            "vulnerable": False,
            "severity": "NONE",
            "package": pkg_name,
            "current_version": project_version,
            "safe_version": f">={safe_version}",
            "rationale": f"The project uses '{pkg_name}' version '{project_version}'. The CVE affects versions less than '{safe_version}'. Since {project_version} >= {safe_version}, the project is NOT vulnerable. No action required.",
            "fix_command": None,
            "action_required": "NONE"
        }
        
        return {
            "instruction": INSTRUCTION_PROMPT,
            "input": input_text,
            "output": json.dumps(output, indent=2, ensure_ascii=False),
            "scenario": "safe",
            "language": lang
        }
    
    def generate_not_found(self) -> Dict:
        """20% - Generate a NOT FOUND scenario (library not in dependency file)"""
        lang = random.choice(["python", "nodejs"])
        
        if lang == "python":
            packages = PYTHON_PACKAGES
            file_type = "requirements.txt"
        else:
            packages = NODE_PACKAGES
            file_type = "package.json"
        
        # Select a package that will be in the CVE
        cve_pkg = random.choice(packages)
        cve_pkg_name = cve_pkg["name"]
        safe_version = random.choice(cve_pkg["versions"][1:])
        
        vuln_type = random.choice(VULNERABILITY_TYPES)
        cve_id = self._generate_cve_id()
        severity = random.choice(["CRITICAL", "HIGH"])
        cvss = self._generate_cvss_score(severity)
        
        # Generate dependency file WITHOUT the CVE package
        if lang == "python":
            dep_file = self._generate_noisy_requirements(cve_pkg_name, None, False, "python")
        else:
            dep_file = self._generate_noisy_package_json(cve_pkg_name, None, False)
        
        cve_report = self._generate_cve_report(cve_id, cve_pkg_name, safe_version, vuln_type, cvss, severity)
        
        input_text = f"""{cve_report}

--- TARGET DEPENDENCY FILE ({file_type}) ---
{dep_file}"""
        
        output = {
            "vulnerable": False,
            "severity": "NONE",
            "package": cve_pkg_name,
            "current_version": None,
            "safe_version": f">={safe_version}",
            "rationale": f"The CVE affects '{cve_pkg_name}', but this library is NOT present in the project's dependency file. The project does not use this package, therefore it is not vulnerable to this specific CVE.",
            "fix_command": None,
            "action_required": "NONE",
            "note": "Consider checking transitive dependencies if this package might be an indirect dependency."
        }
        
        return {
            "instruction": INSTRUCTION_PROMPT,
            "input": input_text,
            "output": json.dumps(output, indent=2, ensure_ascii=False),
            "scenario": "not_found",
            "language": lang
        }
    
    def generate_complex_range(self) -> Dict:
        """10% - Generate a COMPLEX RANGE scenario (e.g., >1.0.0, <1.5.2)"""
        lang = random.choice(["python", "nodejs"])
        
        if lang == "python":
            packages = PYTHON_PACKAGES
            file_type = "requirements.txt"
            cmd_prefix = "pip install"
        else:
            packages = NODE_PACKAGES
            file_type = "package.json"
            cmd_prefix = "npm install"
        
        pkg = random.choice([p for p in packages if len(p["versions"]) >= 5])
        pkg_name = pkg["name"]
        versions = pkg["versions"]
        
        # Define a range: affected versions are between lower_bound and upper_bound
        lower_idx = random.randint(0, len(versions) // 3)
        upper_idx = random.randint(len(versions) // 2, len(versions) - 2)
        
        lower_bound = versions[lower_idx]
        upper_bound = versions[upper_idx]
        safe_version = versions[upper_idx + 1]
        
        # Randomly decide if project is in vulnerable range or not
        is_vulnerable = random.random() > 0.4
        
        if is_vulnerable:
            # Pick version within the affected range
            project_idx = random.randint(lower_idx + 1, upper_idx)
            project_version = versions[project_idx]
        else:
            # Pick version outside the affected range (either before or after)
            if random.random() > 0.5 and upper_idx + 1 < len(versions):
                project_version = versions[random.randint(upper_idx + 1, len(versions) - 1)]
            else:
                project_version = versions[0] if lower_idx > 0 else versions[-1]
                is_vulnerable = self._compare_versions(project_version, lower_bound) > 0 and self._compare_versions(project_version, upper_bound) <= 0
        
        # Verify vulnerability status
        is_in_range = (self._compare_versions(project_version, lower_bound) > 0 and 
                       self._compare_versions(project_version, upper_bound) <= 0)
        is_vulnerable = is_in_range
        
        vuln_type = random.choice(VULNERABILITY_TYPES)
        cve_id = self._generate_cve_id()
        severity = "HIGH" if is_vulnerable else "NONE"
        cvss = self._generate_cvss_score(severity if is_vulnerable else "HIGH")
        
        affected_range = f">{lower_bound}, <={upper_bound}"
        
        if lang == "python":
            dep_file = self._generate_noisy_requirements(pkg_name, project_version, True, "python")
        else:
            dep_file = self._generate_noisy_package_json(pkg_name, project_version, True)
        
        cve_report = self._generate_cve_report(cve_id, pkg_name, safe_version, vuln_type, cvss, 
                                                "HIGH" if is_vulnerable else "HIGH", affected_range)
        
        input_text = f"""{cve_report}

--- TARGET DEPENDENCY FILE ({file_type}) ---
{dep_file}"""
        
        if is_vulnerable:
            output = {
                "vulnerable": True,
                "severity": severity,
                "package": pkg_name,
                "current_version": project_version,
                "safe_version": f">={safe_version}",
                "rationale": f"The project uses '{pkg_name}' version '{project_version}'. The CVE affects versions in range '{affected_range}'. Since {lower_bound} < {project_version} <= {upper_bound}, the project IS vulnerable.",
                "fix_command": f"{cmd_prefix} {pkg_name}>={safe_version}",
                "action_required": "IMMEDIATE_UPDATE"
            }
        else:
            output = {
                "vulnerable": False,
                "severity": "NONE",
                "package": pkg_name,
                "current_version": project_version,
                "safe_version": f">={safe_version}",
                "rationale": f"The project uses '{pkg_name}' version '{project_version}'. The CVE affects versions in range '{affected_range}'. The project's version is outside this range and is NOT vulnerable.",
                "fix_command": None,
                "action_required": "NONE"
            }
        
        return {
            "instruction": INSTRUCTION_PROMPT,
            "input": input_text,
            "output": json.dumps(output, indent=2, ensure_ascii=False),
            "scenario": "complex_range",
            "language": lang,
            "is_vulnerable": is_vulnerable
        }
    
    # ==================== MAIN GENERATION FUNCTIONS ====================
    
    def generate_sample(self) -> Dict:
        """Generate a single sample based on scenario distribution"""
        rand = random.random()
        
        if rand < 0.40:  # 40% Vulnerable
            return self.generate_vulnerable()
        elif rand < 0.70:  # 30% Safe
            return self.generate_safe()
        elif rand < 0.90:  # 20% Not Found
            return self.generate_not_found()
        else:  # 10% Complex Range
            return self.generate_complex_range()
    
    def generate_dataset(
        self, 
        num_samples: int = 1000,
        output_file: str = "training_data.json",
        save_intermediate: bool = True
    ) -> List[Dict]:
        """
        Generate complete dataset
        
        Args:
            num_samples: Number of samples to generate
            output_file: Output file path
            save_intermediate: Save every 100 samples
        """
        print(f"🎯 Generating {num_samples} training samples...")
        print("="*60)
        
        self.generated_data = []
        scenario_counts = {"vulnerable": 0, "safe": 0, "not_found": 0, "complex_range": 0}
        
        start_time = time.time()
        
        for i in range(num_samples):
            sample = self.generate_sample()
            self.generated_data.append(sample)
            scenario_counts[sample["scenario"]] += 1
            
            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                print(f"  ✓ {i + 1}/{num_samples} generated ({elapsed:.1f}s)")
                print(f"    Vulnerable: {scenario_counts['vulnerable']} | Safe: {scenario_counts['safe']} | Not Found: {scenario_counts['not_found']} | Complex: {scenario_counts['complex_range']}")
                
                if save_intermediate:
                    self._save_dataset(output_file)
        
        self._save_dataset(output_file)
        
        elapsed = time.time() - start_time
        print("="*60)
        print(f"✅ Complete! {num_samples} samples generated ({elapsed:.1f}s)")
        print(f"   Output: {output_file}")
        print(f"   Scenario Distribution:")
        for scenario, count in scenario_counts.items():
            pct = (count / num_samples) * 100
            print(f"     {scenario}: {count} ({pct:.1f}%)")
        
        return self.generated_data
    
    def _save_dataset(self, output_file: str):
        """Save dataset to file"""
        # Convert to Alpaca format (instruction, input, output only)
        alpaca_format = []
        for sample in self.generated_data:
            alpaca_format.append({
                "instruction": sample["instruction"],
                "input": sample["input"],
                "output": sample["output"]
            })
        
        # Create directory if needed
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(alpaca_format, f, indent=2, ensure_ascii=False)
        
        # Also save detailed version with metadata
        detailed_file = output_file.replace(".json", "_detailed.json")
        with open(detailed_file, "w", encoding="utf-8") as f:
            json.dump(self.generated_data, f, indent=2, ensure_ascii=False)
    
    def generate_with_gpt4(self, num_samples: int = 100) -> List[Dict]:
        """Generate high-quality samples using GPT-4 as Teacher"""
        if not self.use_gpt:
            print("⚠️ GPT-4 not available. Falling back to rule-based generation.")
            return self.generate_dataset(num_samples)
        
        print(f"🧠 Generating {num_samples} samples with GPT-4 Teacher...")
        
        system_prompt = """You are an expert cybersecurity data engineer creating training data for a security analysis LLM.
Generate realistic CVE vulnerability scenarios for software dependency analysis.

Requirements:
1. Create realistic CVE reports with proper IDs and descriptions
2. Generate messy, real-world dependency files with comments and noise
3. Apply Semantic Versioning correctly (1.2.3 < 1.3.0 < 2.0.0)
4. Output must be valid, parseable JSON
5. Include rationale that explains the version comparison logic

Scenarios to cover:
- Vulnerable: Project uses old version
- Safe: Project already updated
- Not Found: CVE package not in dependencies
- Complex Range: Version ranges like >1.0, <2.0"""

        # TODO: Implement GPT-4 API calls
        # For now, fall back to rule-based
        return self.generate_dataset(num_samples)


# ==================== MAIN ====================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="SentiLLM Training Data Generator v2.0")
    parser.add_argument("--samples", type=int, default=1000, help="Number of samples to generate")
    parser.add_argument("--output", type=str, default="training_data.json", help="Output file path")
    parser.add_argument("--use-gpt", action="store_true", help="Use GPT-4 for generation (requires API key)")
    
    args = parser.parse_args()
    
    # Use global OPENAI_API_KEY loaded from .env
    generator = SyntheticDataGenerator(
        openai_api_key=OPENAI_API_KEY,
        use_gpt=args.use_gpt
    )
    
    generator.generate_dataset(
        num_samples=args.samples,
        output_file=args.output
    )


if __name__ == "__main__":
    main()
