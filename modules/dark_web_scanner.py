"""
Dark Web Scanner Module
Checks for exposed credentials and data breaches
Uses Have I Been Pwned API and simulates dark web monitoring
"""

import hashlib
import urllib.request
import urllib.error
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from config import config


class DarkWebScanner:
    """Check for exposed credentials and data breaches"""

    HIBP_API_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(self):
        self.api_key = config.HIBP_API_KEY
        self.api_configured = bool(self.api_key)

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Scan a domain for breaches and exposed data"""
        scan_start = datetime.now()
        findings = []
        breaches_found = 0
        exposed_credentials = 0

        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith("http"):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        domain = domain.replace("www.", "")

        if not self._is_valid_domain(domain):
            return {
                "domain": domain,
                "status": "error",
                "error": "Invalid domain format",
                "findings": [],
                "risk_score": 0
            }

        # Check domain breaches using HIBP API (if configured)
        if self.api_configured:
            breach_results = self._check_domain_breaches(domain)
            if breach_results:
                findings.extend(breach_results)
                breaches_found = len([f for f in breach_results if f["type"] == "breach"])
        else:
            # Use simulated results for demo
            breach_results = self._simulate_breach_check(domain)
            findings.extend(breach_results)
            breaches_found = len([f for f in breach_results if f["type"] == "breach"])

        # Check for common email patterns at this domain
        common_emails = self._generate_common_emails(domain)
        for email in common_emails[:5]:  # Limit to 5 to avoid rate limiting
            if self.api_configured:
                email_breaches = self._check_email_breaches(email)
            else:
                email_breaches = self._simulate_email_check(email)

            if email_breaches:
                findings.extend(email_breaches)
                exposed_credentials += len(email_breaches)

        # Add dark web monitoring recommendations
        findings.append({
            "type": "recommendation",
            "severity": "INFO",
            "title": "Dark Web Monitoring",
            "description": "Consider implementing continuous dark web monitoring",
            "recommendation": "Set up alerts for new breaches involving your domain",
            "details": {}
        })

        # Calculate risk score
        risk_score = self._calculate_risk_score(findings, breaches_found, exposed_credentials)

        return {
            "domain": domain,
            "status": "completed",
            "scan_duration": (datetime.now() - scan_start).total_seconds(),
            "breaches_found": breaches_found,
            "exposed_credentials": exposed_credentials,
            "findings": findings,
            "risk_score": risk_score,
            "api_mode": "live" if self.api_configured else "simulated",
            "summary": {
                "total_breaches": breaches_found,
                "exposed_accounts": exposed_credentials,
                "critical_findings": len([f for f in findings if f.get("severity") == "CRITICAL"]),
                "high_findings": len([f for f in findings if f.get("severity") == "HIGH"])
            }
        }

    def check_email(self, email: str) -> Dict[str, Any]:
        """Check a single email for breaches"""
        if self.api_configured:
            findings = self._check_email_breaches(email)
        else:
            findings = self._simulate_email_check(email)

        return {
            "email": email,
            "breaches_found": len(findings),
            "findings": findings,
            "checked_at": datetime.now().isoformat()
        }

    def check_password(self, password: str) -> Dict[str, Any]:
        """Check if a password has been exposed in breaches (using k-anonymity)"""
        # Hash the password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            # Query HIBP Passwords API (doesn't require API key)
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            req = urllib.request.Request(url, headers={
                'User-Agent': 'VCSO-Security-Scanner/1.0'
            })

            with urllib.request.urlopen(req, timeout=10) as response:
                data = response.read().decode('utf-8')

                for line in data.splitlines():
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return {
                            "exposed": True,
                            "count": int(count),
                            "message": f"This password has been seen {count} times in data breaches",
                            "severity": "CRITICAL" if int(count) > 100 else "HIGH",
                            "recommendation": "Change this password immediately and use a unique password"
                        }

                return {
                    "exposed": False,
                    "count": 0,
                    "message": "This password was not found in known data breaches",
                    "severity": "INFO",
                    "recommendation": "Continue using strong, unique passwords"
                }

        except Exception as e:
            return {
                "exposed": None,
                "error": str(e),
                "message": "Could not check password against breach database"
            }

    def _check_domain_breaches(self, domain: str) -> List[Dict[str, Any]]:
        """Check domain for breaches using HIBP API"""
        findings = []

        try:
            url = f"{self.HIBP_API_URL}/breaches"
            req = urllib.request.Request(url, headers={
                'User-Agent': 'VCSO-Security-Scanner/1.0',
                'hibp-api-key': self.api_key
            })

            with urllib.request.urlopen(req, timeout=10) as response:
                breaches = json.loads(response.read().decode())

                # Filter breaches that might affect this domain
                # (In reality, you'd need a more sophisticated approach)
                for breach in breaches[:10]:  # Sample of recent breaches
                    findings.append({
                        "type": "breach_info",
                        "severity": "INFO",
                        "title": f"Known Breach: {breach['Name']}",
                        "description": f"Breach occurred on {breach['BreachDate']}",
                        "details": {
                            "name": breach["Name"],
                            "date": breach["BreachDate"],
                            "accounts": breach["PwnCount"],
                            "data_types": breach["DataClasses"]
                        },
                        "recommendation": "Check if any company accounts were affected"
                    })

        except urllib.error.HTTPError as e:
            if e.code == 401:
                findings.append({
                    "type": "error",
                    "severity": "INFO",
                    "title": "API Authentication Required",
                    "description": "HIBP API key needed for domain searches",
                    "recommendation": "Configure HIBP API key for full functionality"
                })
        except Exception as e:
            pass

        return findings

    def _check_email_breaches(self, email: str) -> List[Dict[str, Any]]:
        """Check email for breaches using HIBP API"""
        findings = []

        try:
            encoded_email = urllib.parse.quote(email)
            url = f"{self.HIBP_API_URL}/breachedaccount/{encoded_email}?truncateResponse=false"
            req = urllib.request.Request(url, headers={
                'User-Agent': 'VCSO-Security-Scanner/1.0',
                'hibp-api-key': self.api_key
            })

            with urllib.request.urlopen(req, timeout=10) as response:
                breaches = json.loads(response.read().decode())

                for breach in breaches:
                    severity = "CRITICAL" if "Passwords" in breach.get("DataClasses", []) else "HIGH"
                    findings.append({
                        "type": "breach",
                        "severity": severity,
                        "title": f"Email Found in Breach: {breach['Name']}",
                        "description": f"{email} was exposed in the {breach['Name']} breach",
                        "details": {
                            "email": email,
                            "breach_name": breach["Name"],
                            "breach_date": breach["BreachDate"],
                            "data_exposed": breach["DataClasses"]
                        },
                        "recommendation": "Reset passwords and enable MFA for this account"
                    })

            # Rate limit compliance
            time.sleep(1.5)

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # No breaches found - good!
                pass
            elif e.code == 429:
                findings.append({
                    "type": "rate_limit",
                    "severity": "INFO",
                    "title": "Rate Limited",
                    "description": "Too many requests to breach database",
                    "recommendation": "Try again later"
                })
        except Exception as e:
            pass

        return findings

    def _simulate_breach_check(self, domain: str) -> List[Dict[str, Any]]:
        """Simulate breach check for demo mode"""
        import random

        findings = []

        # Simulate finding some breaches
        simulated_breaches = [
            {
                "name": "Collection #1",
                "date": "2019-01-17",
                "accounts": 772904991,
                "types": ["Email addresses", "Passwords"]
            },
            {
                "name": "LinkedIn",
                "date": "2021-06-22",
                "accounts": 700000000,
                "types": ["Email addresses", "Names", "Phone numbers"]
            },
            {
                "name": "Adobe",
                "date": "2013-10-04",
                "accounts": 152445165,
                "types": ["Email addresses", "Password hints", "Passwords"]
            }
        ]

        # Randomly select some breaches
        num_breaches = random.randint(0, 2)
        selected = random.sample(simulated_breaches, min(num_breaches, len(simulated_breaches)))

        for breach in selected:
            findings.append({
                "type": "breach",
                "severity": "HIGH" if "Passwords" in breach["types"] else "MEDIUM",
                "title": f"Potential Exposure: {breach['name']}",
                "description": f"Accounts from {domain} may have been exposed in {breach['name']} breach",
                "details": {
                    "breach_name": breach["name"],
                    "breach_date": breach["date"],
                    "total_accounts": breach["accounts"],
                    "data_exposed": breach["types"]
                },
                "recommendation": "Verify if company accounts were affected and reset passwords"
            })

        # Add general findings
        findings.append({
            "type": "info",
            "severity": "INFO",
            "title": "Dark Web Monitoring Recommendation",
            "description": f"Consider monitoring {domain} for new breach exposures",
            "recommendation": "Set up continuous dark web monitoring for proactive detection"
        })

        return findings

    def _simulate_email_check(self, email: str) -> List[Dict[str, Any]]:
        """Simulate email breach check for demo mode"""
        import random

        findings = []

        # 30% chance of finding a breach for demo purposes
        if random.random() < 0.3:
            breach_types = [
                ("LinkedIn", "2021-06-22", ["Email addresses", "Names"]),
                ("Dropbox", "2012-07-01", ["Email addresses", "Passwords"]),
                ("MyFitnessPal", "2018-02-01", ["Email addresses", "Passwords", "Usernames"])
            ]

            breach = random.choice(breach_types)
            findings.append({
                "type": "breach",
                "severity": "HIGH" if "Passwords" in breach[2] else "MEDIUM",
                "title": f"Email Found in {breach[0]} Breach",
                "description": f"{email} was found in the {breach[0]} data breach",
                "details": {
                    "email": email,
                    "breach_name": breach[0],
                    "breach_date": breach[1],
                    "data_exposed": breach[2]
                },
                "recommendation": "Reset password and enable MFA for associated accounts"
            })

        return findings

    def _generate_common_emails(self, domain: str) -> List[str]:
        """Generate common email patterns to check"""
        prefixes = [
            "info", "admin", "contact", "support", "sales",
            "hr", "billing", "security", "help", "webmaster"
        ]
        return [f"{prefix}@{domain}" for prefix in prefixes]

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        import re
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))

    def _calculate_risk_score(
        self,
        findings: List[Dict[str, Any]],
        breaches_found: int,
        exposed_credentials: int
    ) -> float:
        """Calculate risk score based on findings"""
        score = 100

        # Deduct for each breach
        score -= breaches_found * 15

        # Deduct for exposed credentials
        score -= exposed_credentials * 10

        # Deduct based on severity
        for finding in findings:
            severity = finding.get("severity", "INFO")
            if severity == "CRITICAL":
                score -= 20
            elif severity == "HIGH":
                score -= 10
            elif severity == "MEDIUM":
                score -= 5

        return max(0, min(100, score))

    def get_breach_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of breach findings"""
        breaches = [f for f in findings if f["type"] == "breach"]

        if not breaches:
            return {
                "status": "clean",
                "message": "No breaches detected for this domain",
                "recommendations": [
                    "Continue monitoring for new breaches",
                    "Implement dark web monitoring service",
                    "Ensure all accounts use unique passwords"
                ]
            }

        # Analyze breach types
        password_breaches = [b for b in breaches if "Passwords" in str(b.get("details", {}).get("data_exposed", []))]

        return {
            "status": "exposed",
            "total_breaches": len(breaches),
            "password_exposures": len(password_breaches),
            "message": f"Found {len(breaches)} breach(es) affecting this domain",
            "recommendations": [
                "Immediately reset passwords for all affected accounts",
                "Enable multi-factor authentication (MFA)",
                "Monitor for suspicious account activity",
                "Consider identity theft protection services",
                "Implement a password manager with breach detection"
            ]
        }
