"""
Git Repository Security Scanner Module
Scans repositories for secrets, vulnerabilities, and security issues
"""

import re
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import urllib.request
import urllib.parse
import base64


@dataclass
class SecretPattern:
    """Pattern for detecting secrets"""
    name: str
    pattern: str
    severity: str
    description: str


class GitScanner:
    """Scan Git repositories for security issues"""

    # Secret detection patterns
    SECRET_PATTERNS = [
        SecretPattern(
            name="AWS Access Key",
            pattern=r'AKIA[0-9A-Z]{16}',
            severity="CRITICAL",
            description="AWS Access Key ID detected"
        ),
        SecretPattern(
            name="AWS Secret Key",
            pattern=r'(?i)aws_secret_access_key\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
            severity="CRITICAL",
            description="AWS Secret Access Key detected"
        ),
        SecretPattern(
            name="GitHub Token",
            pattern=r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}',
            severity="CRITICAL",
            description="GitHub Personal Access Token detected"
        ),
        SecretPattern(
            name="Generic API Key",
            pattern=r'(?i)(api[_-]?key|apikey)\s*[=:]\s*[\'"]?([a-zA-Z0-9]{32,})[\'"]?',
            severity="HIGH",
            description="Generic API key detected"
        ),
        SecretPattern(
            name="Generic Secret",
            pattern=r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'",]{8,})[\'"]?',
            severity="HIGH",
            description="Hardcoded secret or password detected"
        ),
        SecretPattern(
            name="Private Key",
            pattern=r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            severity="CRITICAL",
            description="Private key detected in repository"
        ),
        SecretPattern(
            name="Slack Token",
            pattern=r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            severity="HIGH",
            description="Slack token detected"
        ),
        SecretPattern(
            name="Stripe API Key",
            pattern=r'sk_live_[0-9a-zA-Z]{24}',
            severity="CRITICAL",
            description="Stripe live API key detected"
        ),
        SecretPattern(
            name="Google API Key",
            pattern=r'AIza[0-9A-Za-z\-_]{35}',
            severity="HIGH",
            description="Google API key detected"
        ),
        SecretPattern(
            name="JWT Token",
            pattern=r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            severity="MEDIUM",
            description="JWT token detected (may be test data)"
        ),
        SecretPattern(
            name="Database URL",
            pattern=r'(?i)(mongodb|postgres|mysql|redis):\/\/[^\s\'\"]+',
            severity="HIGH",
            description="Database connection string detected"
        ),
        SecretPattern(
            name="SSH URL with Password",
            pattern=r'ssh:\/\/[^:]+:[^@]+@',
            severity="CRITICAL",
            description="SSH URL with embedded password"
        )
    ]

    # Dangerous file patterns
    DANGEROUS_FILES = [
        (".env", "CRITICAL", "Environment file may contain secrets"),
        (".env.local", "CRITICAL", "Local environment file may contain secrets"),
        (".env.production", "CRITICAL", "Production environment file detected"),
        ("credentials.json", "CRITICAL", "Credentials file detected"),
        ("secrets.yml", "CRITICAL", "Secrets file detected"),
        ("secrets.yaml", "CRITICAL", "Secrets file detected"),
        (".npmrc", "HIGH", "NPM config may contain auth tokens"),
        (".pypirc", "HIGH", "PyPI config may contain auth tokens"),
        ("id_rsa", "CRITICAL", "Private SSH key detected"),
        ("id_ed25519", "CRITICAL", "Private SSH key detected"),
        (".htpasswd", "HIGH", "Apache password file detected"),
        ("wp-config.php", "HIGH", "WordPress config may contain database credentials"),
        ("config.php", "MEDIUM", "PHP config file may contain secrets"),
        ("application.properties", "MEDIUM", "Java config may contain secrets"),
        ("application.yml", "MEDIUM", "Java config may contain secrets"),
        (".docker/config.json", "HIGH", "Docker config may contain registry credentials")
    ]

    def __init__(self):
        self.compiled_patterns = [
            (p, re.compile(p.pattern, re.MULTILINE))
            for p in self.SECRET_PATTERNS
        ]

    def scan_repository(self, repo_url: str) -> Dict[str, Any]:
        """Scan a repository for security issues"""
        findings = []
        scan_start = datetime.now()

        # Parse repository URL
        repo_info = self._parse_repo_url(repo_url)
        if not repo_info:
            return {
                "repo_url": repo_url,
                "status": "error",
                "error": "Invalid repository URL. Supported: GitHub, GitLab, Bitbucket",
                "findings": [],
                "risk_score": 0
            }

        # Get repository files
        try:
            files = self._get_repo_files(repo_info)
        except Exception as e:
            return {
                "repo_url": repo_url,
                "status": "error",
                "error": f"Failed to access repository: {str(e)}",
                "findings": [],
                "risk_score": 0
            }

        secrets_found = 0
        vulnerabilities_found = 0

        # Scan each file
        for file_info in files:
            # Check for dangerous files
            for dangerous_file, severity, description in self.DANGEROUS_FILES:
                if file_info["name"].endswith(dangerous_file) or file_info["name"] == dangerous_file:
                    findings.append({
                        "type": "dangerous_file",
                        "severity": severity,
                        "file": file_info["path"],
                        "title": f"Sensitive File: {dangerous_file}",
                        "description": description,
                        "recommendation": f"Remove {dangerous_file} from repository and add to .gitignore"
                    })
                    if severity in ["CRITICAL", "HIGH"]:
                        secrets_found += 1

            # Scan file content for secrets (if accessible)
            if file_info.get("content"):
                content = file_info["content"]
                for pattern, compiled in self.compiled_patterns:
                    matches = compiled.findall(content)
                    if matches:
                        findings.append({
                            "type": "secret",
                            "severity": pattern.severity,
                            "file": file_info["path"],
                            "title": pattern.name,
                            "description": pattern.description,
                            "matches": len(matches) if isinstance(matches, list) else 1,
                            "recommendation": f"Remove {pattern.name} from code and rotate the credential"
                        })
                        secrets_found += 1

        # Check for security configuration files
        security_findings = self._check_security_configs(files)
        findings.extend(security_findings)

        # Check for dependency vulnerabilities (if package files exist)
        dep_findings = self._check_dependencies(files)
        findings.extend(dep_findings)
        vulnerabilities_found = len([f for f in dep_findings if f["type"] == "vulnerability"])

        # Calculate risk score
        risk_score = self._calculate_risk_score(findings)

        return {
            "repo_url": repo_url,
            "status": "completed",
            "scan_duration": (datetime.now() - scan_start).total_seconds(),
            "files_scanned": len(files),
            "secrets_found": secrets_found,
            "vulnerabilities_found": vulnerabilities_found,
            "findings": findings,
            "risk_score": risk_score,
            "summary": {
                "critical_findings": len([f for f in findings if f["severity"] == "CRITICAL"]),
                "high_findings": len([f for f in findings if f["severity"] == "HIGH"]),
                "medium_findings": len([f for f in findings if f["severity"] == "MEDIUM"]),
                "low_findings": len([f for f in findings if f["severity"] == "LOW"])
            }
        }

    def _parse_repo_url(self, url: str) -> Optional[Dict[str, str]]:
        """Parse repository URL to extract platform and repo info"""
        patterns = [
            (r'github\.com[/:]([^/]+)/([^/\.]+)', 'github'),
            (r'gitlab\.com[/:]([^/]+)/([^/\.]+)', 'gitlab'),
            (r'bitbucket\.org[/:]([^/]+)/([^/\.]+)', 'bitbucket')
        ]

        for pattern, platform in patterns:
            match = re.search(pattern, url)
            if match:
                return {
                    "platform": platform,
                    "owner": match.group(1),
                    "repo": match.group(2).replace('.git', '')
                }
        return None

    def _get_repo_files(self, repo_info: Dict[str, str]) -> List[Dict[str, Any]]:
        """Get list of files from repository (public repos only)"""
        files = []

        if repo_info["platform"] == "github":
            # Use GitHub API to get repo tree
            api_url = f"https://api.github.com/repos/{repo_info['owner']}/{repo_info['repo']}/git/trees/main?recursive=1"

            try:
                req = urllib.request.Request(api_url, headers={
                    'User-Agent': 'VCSO-Security-Scanner/1.0',
                    'Accept': 'application/vnd.github.v3+json'
                })
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())

                    for item in data.get("tree", []):
                        if item["type"] == "blob":
                            file_info = {
                                "path": item["path"],
                                "name": item["path"].split("/")[-1],
                                "sha": item["sha"],
                                "size": item.get("size", 0)
                            }

                            # Get content for small text files
                            if item.get("size", 0) < 100000:  # < 100KB
                                content = self._get_file_content_github(
                                    repo_info["owner"],
                                    repo_info["repo"],
                                    item["path"]
                                )
                                if content:
                                    file_info["content"] = content

                            files.append(file_info)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    # Try 'master' branch
                    api_url = api_url.replace("/main?", "/master?")
                    req = urllib.request.Request(api_url, headers={
                        'User-Agent': 'VCSO-Security-Scanner/1.0',
                        'Accept': 'application/vnd.github.v3+json'
                    })
                    with urllib.request.urlopen(req, timeout=10) as response:
                        data = json.loads(response.read().decode())
                        for item in data.get("tree", []):
                            if item["type"] == "blob":
                                files.append({
                                    "path": item["path"],
                                    "name": item["path"].split("/")[-1],
                                    "sha": item["sha"],
                                    "size": item.get("size", 0)
                                })
                else:
                    raise

        return files

    def _get_file_content_github(self, owner: str, repo: str, path: str) -> Optional[str]:
        """Get file content from GitHub"""
        try:
            api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            req = urllib.request.Request(api_url, headers={
                'User-Agent': 'VCSO-Security-Scanner/1.0',
                'Accept': 'application/vnd.github.v3+json'
            })
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                if data.get("encoding") == "base64":
                    return base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
        except:
            pass
        return None

    def _check_security_configs(self, files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for security-related configuration files"""
        findings = []
        file_names = [f["name"] for f in files]
        file_paths = [f["path"] for f in files]

        # Check for .gitignore
        if ".gitignore" not in file_names:
            findings.append({
                "type": "config",
                "severity": "MEDIUM",
                "file": None,
                "title": "Missing .gitignore",
                "description": "Repository does not have a .gitignore file",
                "recommendation": "Add a .gitignore file to prevent accidental commits of sensitive files"
            })

        # Check for security policy
        has_security_policy = any(
            "SECURITY.md" in p or "security.md" in p or ".github/SECURITY.md" in p
            for p in file_paths
        )
        if not has_security_policy:
            findings.append({
                "type": "config",
                "severity": "LOW",
                "file": None,
                "title": "Missing Security Policy",
                "description": "Repository does not have a SECURITY.md file",
                "recommendation": "Add a SECURITY.md file to document vulnerability reporting process"
            })

        # Check for dependency lock files
        has_lock_file = any(
            name in file_names for name in
            ["package-lock.json", "yarn.lock", "Gemfile.lock", "poetry.lock", "Pipfile.lock", "go.sum"]
        )
        has_package_file = any(
            name in file_names for name in
            ["package.json", "Gemfile", "requirements.txt", "go.mod", "Cargo.toml"]
        )
        if has_package_file and not has_lock_file:
            findings.append({
                "type": "config",
                "severity": "MEDIUM",
                "file": None,
                "title": "Missing Dependency Lock File",
                "description": "Package manager detected but no lock file found",
                "recommendation": "Add a lock file to ensure reproducible builds and prevent supply chain attacks"
            })

        # Check for CI/CD security
        has_ci = any(
            ".github/workflows" in p or ".gitlab-ci.yml" in p or "Jenkinsfile" in p
            for p in file_paths
        )
        if has_ci:
            findings.append({
                "type": "info",
                "severity": "INFO",
                "file": None,
                "title": "CI/CD Pipeline Detected",
                "description": "Repository has CI/CD configuration",
                "recommendation": "Ensure CI/CD secrets are properly secured and not logged"
            })

        return findings

    def _check_dependencies(self, files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for known vulnerable dependencies (basic check)"""
        findings = []

        # Find package files
        for file_info in files:
            if file_info["name"] == "package.json" and file_info.get("content"):
                try:
                    pkg = json.loads(file_info["content"])
                    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

                    # Check for known problematic packages
                    vulnerable_packages = {
                        "event-stream": "Known malicious package (flatmap-stream incident)",
                        "ua-parser-js": "Had malicious versions published",
                        "coa": "Had malicious versions published",
                        "rc": "Had malicious versions published",
                        "lodash": "Multiple prototype pollution vulnerabilities in older versions"
                    }

                    for pkg_name, warning in vulnerable_packages.items():
                        if pkg_name in deps:
                            findings.append({
                                "type": "vulnerability",
                                "severity": "MEDIUM",
                                "file": file_info["path"],
                                "title": f"Potentially Vulnerable Package: {pkg_name}",
                                "description": warning,
                                "recommendation": f"Review {pkg_name} version and update if necessary"
                            })

                    # Check for outdated patterns
                    if "request" in deps:
                        findings.append({
                            "type": "vulnerability",
                            "severity": "LOW",
                            "file": file_info["path"],
                            "title": "Deprecated Package: request",
                            "description": "The 'request' package is deprecated",
                            "recommendation": "Migrate to 'node-fetch', 'axios', or 'got'"
                        })

                except json.JSONDecodeError:
                    pass

            elif file_info["name"] == "requirements.txt" and file_info.get("content"):
                # Basic Python dependency check
                content = file_info["content"]
                vulnerable_python_packages = {
                    "pyyaml": "Ensure version >= 5.4 to avoid arbitrary code execution",
                    "django": "Ensure using latest security patches",
                    "flask": "Check for security updates",
                    "requests": "Check for security updates",
                    "urllib3": "Multiple vulnerabilities in older versions"
                }

                for pkg_name, warning in vulnerable_python_packages.items():
                    if pkg_name.lower() in content.lower():
                        findings.append({
                            "type": "info",
                            "severity": "INFO",
                            "file": file_info["path"],
                            "title": f"Dependency Note: {pkg_name}",
                            "description": warning,
                            "recommendation": "Run security audit with 'pip-audit' or 'safety check'"
                        })

        return findings

    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate risk score based on findings"""
        score = 100

        for finding in findings:
            severity = finding.get("severity", "INFO")
            if severity == "CRITICAL":
                score -= 25
            elif severity == "HIGH":
                score -= 15
            elif severity == "MEDIUM":
                score -= 8
            elif severity == "LOW":
                score -= 3

        return max(0, min(100, score))

    def simulate_scan(self, repo_url: str) -> Dict[str, Any]:
        """Simulate a scan for demo purposes"""
        import random

        # Generate realistic findings based on common issues
        findings = []

        # Simulate some findings
        if random.random() > 0.3:
            findings.append({
                "type": "config",
                "severity": "MEDIUM",
                "file": None,
                "title": "Missing Security Policy",
                "description": "Repository does not have a SECURITY.md file",
                "recommendation": "Add a SECURITY.md file to document vulnerability reporting process"
            })

        if random.random() > 0.5:
            findings.append({
                "type": "secret",
                "severity": "HIGH",
                "file": "src/config.js",
                "title": "Generic API Key",
                "description": "Generic API key detected",
                "recommendation": "Remove API key from code and use environment variables"
            })

        if random.random() > 0.7:
            findings.append({
                "type": "dangerous_file",
                "severity": "HIGH",
                "file": ".env.example",
                "title": "Sensitive File: .env.example",
                "description": "Environment example file may reveal configuration structure",
                "recommendation": "Ensure no real values in example files"
            })

        if random.random() > 0.6:
            findings.append({
                "type": "vulnerability",
                "severity": "MEDIUM",
                "file": "package.json",
                "title": "Deprecated Package: request",
                "description": "The 'request' package is deprecated",
                "recommendation": "Migrate to 'node-fetch', 'axios', or 'got'"
            })

        return {
            "repo_url": repo_url,
            "status": "completed",
            "scan_duration": random.uniform(2, 8),
            "files_scanned": random.randint(50, 200),
            "secrets_found": len([f for f in findings if f["type"] == "secret"]),
            "vulnerabilities_found": len([f for f in findings if f["type"] == "vulnerability"]),
            "findings": findings,
            "risk_score": self._calculate_risk_score(findings),
            "demo_mode": True,
            "summary": {
                "critical_findings": len([f for f in findings if f["severity"] == "CRITICAL"]),
                "high_findings": len([f for f in findings if f["severity"] == "HIGH"]),
                "medium_findings": len([f for f in findings if f["severity"] == "MEDIUM"]),
                "low_findings": len([f for f in findings if f["severity"] == "LOW"])
            }
        }
