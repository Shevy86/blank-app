"""
Report Generator Module
Generates comprehensive security assessment reports
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
from config import config, RISK_LEVELS, SOC2_CATEGORIES


@dataclass
class ReportSection:
    """Report section"""
    title: str
    score: float
    risk_level: str
    findings: List[Dict[str, Any]]
    recommendations: List[str]


class ReportGenerator:
    """Generate comprehensive security assessment reports"""

    def __init__(self):
        self.company_name = config.COMPANY_NAME
        self.company_website = config.COMPANY_WEBSITE

    def generate_report(
        self,
        assessment_id: str,
        company_info: Dict[str, Any],
        soc2_results: Dict[str, Any],
        vulnerability_results: List[Dict[str, Any]],
        phishing_results: Dict[str, Any],
        git_results: List[Dict[str, Any]],
        dark_web_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a comprehensive assessment report"""

        # Calculate overall score
        scores = []
        if soc2_results.get("overall_score"):
            scores.append(soc2_results["overall_score"])

        for vuln in vulnerability_results:
            if vuln.get("risk_score"):
                scores.append(vuln["risk_score"])

        if phishing_results.get("risk_score"):
            scores.append(phishing_results["risk_score"])

        for git in git_results:
            if git.get("risk_score"):
                scores.append(git["risk_score"])

        if dark_web_results.get("risk_score"):
            scores.append(dark_web_results["risk_score"])

        overall_score = sum(scores) / len(scores) if scores else 0
        overall_risk_level = self._get_risk_level(overall_score)

        # Build report
        report = {
            "metadata": {
                "report_id": assessment_id,
                "generated_at": datetime.now().isoformat(),
                "generated_by": self.company_name,
                "report_version": "1.0"
            },
            "company_info": company_info,
            "executive_summary": self._generate_executive_summary(
                overall_score,
                overall_risk_level,
                soc2_results,
                vulnerability_results,
                phishing_results,
                git_results,
                dark_web_results
            ),
            "overall_score": round(overall_score, 1),
            "overall_risk_level": overall_risk_level,
            "sections": {
                "soc2_assessment": self._format_soc2_section(soc2_results),
                "vulnerability_scan": self._format_vulnerability_section(vulnerability_results),
                "phishing_test": self._format_phishing_section(phishing_results),
                "git_security": self._format_git_section(git_results),
                "dark_web": self._format_dark_web_section(dark_web_results)
            },
            "priority_recommendations": self._generate_priority_recommendations(
                soc2_results,
                vulnerability_results,
                phishing_results,
                git_results,
                dark_web_results
            ),
            "compliance_gaps": self._identify_compliance_gaps(soc2_results),
            "next_steps": self._generate_next_steps(overall_score, overall_risk_level),
            "appendix": {
                "methodology": self._get_methodology(),
                "risk_rating_scale": RISK_LEVELS,
                "disclaimer": self._get_disclaimer()
            }
        }

        return report

    def _generate_executive_summary(
        self,
        overall_score: float,
        risk_level: str,
        soc2_results: Dict,
        vulnerability_results: List[Dict],
        phishing_results: Dict,
        git_results: List[Dict],
        dark_web_results: Dict
    ) -> Dict[str, Any]:
        """Generate executive summary"""

        # Count critical findings
        critical_findings = 0
        high_findings = 0

        # From vulnerability scans
        for vuln in vulnerability_results:
            summary = vuln.get("summary", {})
            critical_findings += summary.get("critical_findings", 0)
            high_findings += summary.get("high_findings", 0)

        # From git scans
        for git in git_results:
            summary = git.get("summary", {})
            critical_findings += summary.get("critical_findings", 0)
            high_findings += summary.get("high_findings", 0)

        # From dark web
        if dark_web_results:
            summary = dark_web_results.get("summary", {})
            critical_findings += summary.get("critical_findings", 0)
            high_findings += summary.get("high_findings", 0)

        # Determine overall status
        if overall_score >= 80:
            status = "Good"
            status_description = "Your organization demonstrates a strong security posture with room for improvement in specific areas."
        elif overall_score >= 60:
            status = "Moderate"
            status_description = "Your organization has foundational security controls but requires attention in several key areas."
        elif overall_score >= 40:
            status = "Needs Improvement"
            status_description = "Your organization has significant security gaps that should be addressed promptly."
        else:
            status = "Critical"
            status_description = "Your organization has critical security vulnerabilities requiring immediate attention."

        return {
            "overall_status": status,
            "overall_score": round(overall_score, 1),
            "risk_level": risk_level,
            "status_description": status_description,
            "key_metrics": {
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "soc2_readiness": f"{soc2_results.get('overall_score', 0):.0f}%",
                "phishing_resilience": f"{phishing_results.get('risk_score', 0):.0f}%"
            },
            "key_findings": self._get_key_findings(
                vulnerability_results, git_results, dark_web_results
            ),
            "immediate_actions": self._get_immediate_actions(
                critical_findings, high_findings, soc2_results
            )
        }

    def _format_soc2_section(self, soc2_results: Dict) -> Dict[str, Any]:
        """Format SOC2 assessment section"""
        category_scores = soc2_results.get("category_scores", {})

        return {
            "title": "SOC2 Type 1 Readiness Assessment",
            "overall_score": soc2_results.get("overall_score", 0),
            "risk_level": soc2_results.get("risk_level", "UNKNOWN"),
            "category_breakdown": {
                cat: {
                    "name": SOC2_CATEGORIES.get(cat, cat),
                    "score": score,
                    "status": "Pass" if score >= 70 else "Needs Work"
                }
                for cat, score in category_scores.items()
            },
            "questions_answered": soc2_results.get("questions_answered", 0),
            "total_questions": soc2_results.get("total_questions", 0),
            "readiness_status": self._get_soc2_readiness_status(soc2_results.get("overall_score", 0)),
            "recommendations": soc2_results.get("recommendations", [])
        }

    def _format_vulnerability_section(self, vulnerability_results: List[Dict]) -> Dict[str, Any]:
        """Format vulnerability scan section"""
        all_findings = []
        total_critical = 0
        total_high = 0
        total_medium = 0

        for result in vulnerability_results:
            findings = result.get("findings", [])
            all_findings.extend(findings)

            summary = result.get("summary", {})
            total_critical += summary.get("critical_findings", 0)
            total_high += summary.get("high_findings", 0)
            total_medium += summary.get("medium_findings", 0)

        avg_score = sum(r.get("risk_score", 0) for r in vulnerability_results) / len(vulnerability_results) if vulnerability_results else 0

        return {
            "title": "Vulnerability Assessment",
            "targets_scanned": len(vulnerability_results),
            "overall_score": round(avg_score, 1),
            "summary": {
                "critical": total_critical,
                "high": total_high,
                "medium": total_medium
            },
            "findings_by_target": [
                {
                    "target": r.get("target"),
                    "type": r.get("target_type"),
                    "score": r.get("risk_score", 0),
                    "findings": r.get("findings", [])
                }
                for r in vulnerability_results
            ],
            "top_vulnerabilities": sorted(
                all_findings,
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.get("severity", "INFO"), 5)
            )[:10]
        }

    def _format_phishing_section(self, phishing_results: Dict) -> Dict[str, Any]:
        """Format phishing test section"""
        return {
            "title": "Phishing Awareness Assessment",
            "emails_tested": phishing_results.get("total_emails", 0),
            "metrics": {
                "open_rate": f"{phishing_results.get('open_rate', 0)}%",
                "click_rate": f"{phishing_results.get('click_rate', 0)}%",
                "report_rate": f"{phishing_results.get('report_rate', 0)}%"
            },
            "risk_score": phishing_results.get("risk_score", 0),
            "risk_level": phishing_results.get("risk_level", "UNKNOWN"),
            "interpretation": self._interpret_phishing_results(phishing_results),
            "recommendations": phishing_results.get("recommendations", [])
        }

    def _format_git_section(self, git_results: List[Dict]) -> Dict[str, Any]:
        """Format Git security section"""
        total_secrets = sum(r.get("secrets_found", 0) for r in git_results)
        total_vulns = sum(r.get("vulnerabilities_found", 0) for r in git_results)

        all_findings = []
        for result in git_results:
            all_findings.extend(result.get("findings", []))

        avg_score = sum(r.get("risk_score", 0) for r in git_results) / len(git_results) if git_results else 100

        return {
            "title": "Repository Security Assessment",
            "repositories_scanned": len(git_results),
            "overall_score": round(avg_score, 1),
            "summary": {
                "secrets_detected": total_secrets,
                "vulnerabilities_found": total_vulns,
                "total_findings": len(all_findings)
            },
            "findings_by_repo": [
                {
                    "repo": r.get("repo_url"),
                    "score": r.get("risk_score", 0),
                    "secrets": r.get("secrets_found", 0),
                    "vulnerabilities": r.get("vulnerabilities_found", 0),
                    "findings": r.get("findings", [])
                }
                for r in git_results
            ],
            "critical_findings": [f for f in all_findings if f.get("severity") == "CRITICAL"]
        }

    def _format_dark_web_section(self, dark_web_results: Dict) -> Dict[str, Any]:
        """Format Dark Web monitoring section"""
        return {
            "title": "Dark Web Exposure Assessment",
            "domain_checked": dark_web_results.get("domain", ""),
            "overall_score": dark_web_results.get("risk_score", 0),
            "summary": {
                "breaches_found": dark_web_results.get("breaches_found", 0),
                "exposed_credentials": dark_web_results.get("exposed_credentials", 0)
            },
            "findings": dark_web_results.get("findings", []),
            "breach_details": [
                f for f in dark_web_results.get("findings", [])
                if f.get("type") == "breach"
            ],
            "recommendations": [
                "Monitor the dark web continuously for new exposures",
                "Reset passwords for any exposed accounts",
                "Enable multi-factor authentication on all accounts",
                "Consider identity theft protection services"
            ]
        }

    def _generate_priority_recommendations(
        self,
        soc2_results: Dict,
        vulnerability_results: List[Dict],
        phishing_results: Dict,
        git_results: List[Dict],
        dark_web_results: Dict
    ) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations"""
        recommendations = []

        # Critical vulnerability findings
        for vuln in vulnerability_results:
            for finding in vuln.get("findings", []):
                if finding.get("severity") == "CRITICAL":
                    recommendations.append({
                        "priority": "CRITICAL",
                        "category": "Vulnerability",
                        "issue": finding.get("title"),
                        "recommendation": finding.get("recommendation"),
                        "effort": "Immediate"
                    })

        # Git secrets
        for git in git_results:
            for finding in git.get("findings", []):
                if finding.get("type") == "secret" and finding.get("severity") in ["CRITICAL", "HIGH"]:
                    recommendations.append({
                        "priority": "CRITICAL",
                        "category": "Code Security",
                        "issue": finding.get("title"),
                        "recommendation": finding.get("recommendation"),
                        "effort": "Immediate"
                    })

        # Dark web exposures
        if dark_web_results.get("breaches_found", 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Data Exposure",
                "issue": f"{dark_web_results['breaches_found']} breach(es) detected",
                "recommendation": "Reset passwords and enable MFA for all affected accounts",
                "effort": "1-2 days"
            })

        # Phishing risk
        if phishing_results.get("click_rate", 0) > 20:
            recommendations.append({
                "priority": "HIGH",
                "category": "Human Risk",
                "issue": f"High phishing click rate ({phishing_results['click_rate']}%)",
                "recommendation": "Implement mandatory security awareness training",
                "effort": "1-2 weeks"
            })

        # SOC2 gaps
        for rec in soc2_results.get("recommendations", [])[:5]:
            recommendations.append({
                "priority": rec.get("priority", "MEDIUM"),
                "category": "Compliance",
                "issue": rec.get("question", rec.get("current_state", "")),
                "recommendation": rec.get("recommendation"),
                "effort": "Varies"
            })

        # Sort by priority
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))

        return recommendations[:15]  # Top 15 recommendations

    def _identify_compliance_gaps(self, soc2_results: Dict) -> List[Dict[str, Any]]:
        """Identify SOC2 compliance gaps"""
        gaps = []

        category_scores = soc2_results.get("category_scores", {})
        for cat, score in category_scores.items():
            if score < 70:
                gaps.append({
                    "category": SOC2_CATEGORIES.get(cat, cat),
                    "category_code": cat,
                    "current_score": score,
                    "target_score": 70,
                    "gap": 70 - score,
                    "status": "Critical Gap" if score < 50 else "Needs Improvement"
                })

        return sorted(gaps, key=lambda x: x["current_score"])

    def _generate_next_steps(self, overall_score: float, risk_level: str) -> List[Dict[str, Any]]:
        """Generate recommended next steps"""
        steps = []

        if overall_score < 50:
            steps.extend([
                {
                    "step": 1,
                    "action": "Schedule Security Consultation",
                    "description": "Your assessment reveals critical gaps. We recommend scheduling a consultation with VCSO.AI for remediation planning.",
                    "timeline": "This week",
                    "contact": config.COMPANY_EMAIL
                },
                {
                    "step": 2,
                    "action": "Address Critical Findings",
                    "description": "Immediately address all critical and high-severity findings identified in this report.",
                    "timeline": "Within 2 weeks"
                },
                {
                    "step": 3,
                    "action": "Implement Security Controls",
                    "description": "Work with VCSO.AI to implement missing security controls identified in the SOC2 assessment.",
                    "timeline": "1-3 months"
                }
            ])
        elif overall_score < 75:
            steps.extend([
                {
                    "step": 1,
                    "action": "Review Priority Recommendations",
                    "description": "Address the high-priority recommendations in this report.",
                    "timeline": "Within 30 days"
                },
                {
                    "step": 2,
                    "action": "Enhance Security Program",
                    "description": "Consider engaging VCSO.AI for security program development.",
                    "timeline": "1-2 months"
                },
                {
                    "step": 3,
                    "action": "Re-assess",
                    "description": "Conduct a follow-up assessment after implementing changes.",
                    "timeline": "Quarterly"
                }
            ])
        else:
            steps.extend([
                {
                    "step": 1,
                    "action": "Maintain Security Posture",
                    "description": "Continue your security program and address remaining findings.",
                    "timeline": "Ongoing"
                },
                {
                    "step": 2,
                    "action": "Consider SOC2 Certification",
                    "description": "Your readiness score suggests you may be ready for formal SOC2 Type 1 certification.",
                    "timeline": "3-6 months"
                },
                {
                    "step": 3,
                    "action": "Continuous Monitoring",
                    "description": "Implement ongoing security monitoring and regular assessments.",
                    "timeline": "Ongoing"
                }
            ])

        # Always add training recommendation
        steps.append({
            "step": len(steps) + 1,
            "action": "Security Awareness Training",
            "description": "Subscribe to VCSO.AI's monthly security awareness training program.",
            "timeline": "Ongoing",
            "link": f"{config.COMPANY_WEBSITE}/training"
        })

        return steps

    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score"""
        if score >= 90:
            return "MINIMAL"
        elif score >= 75:
            return "LOW"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 25:
            return "HIGH"
        else:
            return "CRITICAL"

    def _get_soc2_readiness_status(self, score: float) -> str:
        """Get SOC2 readiness status"""
        if score >= 80:
            return "Ready for SOC2 Type 1 audit with minor remediation"
        elif score >= 60:
            return "Approaching readiness - address identified gaps"
        elif score >= 40:
            return "Significant work needed before SOC2 readiness"
        else:
            return "Not ready - fundamental controls missing"

    def _interpret_phishing_results(self, results: Dict) -> str:
        """Interpret phishing test results"""
        click_rate = results.get("click_rate", 0)

        if click_rate <= 5:
            return "Excellent - Your team demonstrates strong phishing awareness."
        elif click_rate <= 15:
            return "Good - Most employees recognize phishing attempts, but some additional training would be beneficial."
        elif click_rate <= 30:
            return "Moderate - A significant portion of employees are susceptible to phishing. Training is recommended."
        else:
            return "High Risk - Many employees clicked on the phishing simulation. Immediate training is critical."

    def _get_key_findings(
        self,
        vulnerability_results: List[Dict],
        git_results: List[Dict],
        dark_web_results: Dict
    ) -> List[str]:
        """Get key findings for executive summary"""
        findings = []

        # Vulnerability findings
        for vuln in vulnerability_results:
            critical = vuln.get("summary", {}).get("critical_findings", 0)
            if critical > 0:
                findings.append(f"{critical} critical vulnerabilities found in {vuln.get('target')}")

        # Git findings
        for git in git_results:
            secrets = git.get("secrets_found", 0)
            if secrets > 0:
                findings.append(f"{secrets} secrets/credentials found in code repository")

        # Dark web
        breaches = dark_web_results.get("breaches_found", 0)
        if breaches > 0:
            findings.append(f"{breaches} data breach exposures detected")

        if not findings:
            findings.append("No critical security issues identified")

        return findings[:5]

    def _get_immediate_actions(
        self,
        critical_findings: int,
        high_findings: int,
        soc2_results: Dict
    ) -> List[str]:
        """Get immediate action items"""
        actions = []

        if critical_findings > 0:
            actions.append(f"Address {critical_findings} critical findings immediately")

        if high_findings > 0:
            actions.append(f"Review and remediate {high_findings} high-severity issues")

        soc2_score = soc2_results.get("overall_score", 0)
        if soc2_score < 50:
            actions.append("Implement fundamental security controls")

        if not actions:
            actions.append("Continue maintaining your security program")
            actions.append("Consider advancing to SOC2 certification")

        return actions

    def _get_methodology(self) -> Dict[str, Any]:
        """Get assessment methodology description"""
        return {
            "overview": "This assessment was conducted using automated security scanning and AI-powered analysis.",
            "components": [
                {
                    "name": "SOC2 Readiness Assessment",
                    "description": "Self-assessment questionnaire based on AICPA Trust Service Criteria"
                },
                {
                    "name": "Vulnerability Scanning",
                    "description": "Port scanning and web application security header analysis"
                },
                {
                    "name": "Phishing Simulation",
                    "description": "Simulated phishing campaign to assess human risk factors"
                },
                {
                    "name": "Code Repository Scan",
                    "description": "Analysis for exposed secrets, credentials, and security misconfigurations"
                },
                {
                    "name": "Dark Web Monitoring",
                    "description": "Search for exposed credentials and data breach involvement"
                }
            ],
            "limitations": [
                "This assessment provides a point-in-time snapshot",
                "Automated scans may not detect all vulnerabilities",
                "This does not constitute a formal SOC2 audit",
                "Results should be validated by security professionals"
            ]
        }

    def _get_disclaimer(self) -> str:
        """Get report disclaimer"""
        return f"""
DISCLAIMER

This security assessment report is provided by {config.COMPANY_NAME} for informational purposes only.

1. This assessment does not guarantee the identification of all security vulnerabilities.
2. This report does not constitute a formal SOC2 audit or certification.
3. Security threats evolve continuously; point-in-time assessments have inherent limitations.
4. Implementation of recommendations should be validated by qualified security professionals.
5. {config.COMPANY_NAME} is not liable for any damages arising from the use of this report.

For comprehensive security guidance and SOC2 certification assistance, please contact {config.COMPANY_EMAIL}.
"""

    def export_to_html(self, report: Dict[str, Any]) -> str:
        """Export report to HTML format"""
        # Generate HTML report
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {report['company_info'].get('company_name', 'Company')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .score-card {{ display: inline-block; background: white; padding: 20px; border-radius: 10px; margin: 10px; text-align: center; }}
        .score {{ font-size: 48px; font-weight: bold; }}
        .score.critical {{ color: #dc3545; }}
        .score.high {{ color: #fd7e14; }}
        .score.medium {{ color: #ffc107; }}
        .score.low {{ color: #28a745; }}
        .score.minimal {{ color: #20c997; }}
        .section {{ background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .section h2 {{ color: #1a1a2e; border-bottom: 2px solid #16213e; padding-bottom: 10px; }}
        .finding {{ background: white; padding: 15px; border-left: 4px solid #ddd; margin: 10px 0; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #1a1a2e; color: white; }}
        .recommendation {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .cta {{ background: #16213e; color: white; padding: 30px; border-radius: 10px; text-align: center; margin-top: 30px; }}
        .cta a {{ color: #4da6ff; }}
        @media print {{ .cta {{ display: none; }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Prepared for: {report['company_info'].get('company_name', 'Company')}</p>
        <p>Generated: {report['metadata']['generated_at'][:10]}</p>
        <p>Report ID: {report['metadata']['report_id'][:8]}...</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div style="text-align: center;">
            <div class="score-card">
                <div class="score {report['overall_risk_level'].lower()}">{report['overall_score']}</div>
                <div>Overall Score</div>
                <div><strong>{report['overall_risk_level']}</strong> Risk</div>
            </div>
        </div>
        <p>{report['executive_summary']['status_description']}</p>

        <h3>Key Metrics</h3>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Critical Findings</td><td>{report['executive_summary']['key_metrics']['critical_findings']}</td></tr>
            <tr><td>High Findings</td><td>{report['executive_summary']['key_metrics']['high_findings']}</td></tr>
            <tr><td>SOC2 Readiness</td><td>{report['executive_summary']['key_metrics']['soc2_readiness']}</td></tr>
            <tr><td>Phishing Resilience</td><td>{report['executive_summary']['key_metrics']['phishing_resilience']}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Priority Recommendations</h2>
        {"".join(f'''
        <div class="finding {r['priority'].lower()}">
            <strong>[{r['priority']}]</strong> {r['category']}<br>
            <strong>Issue:</strong> {r['issue']}<br>
            <strong>Recommendation:</strong> {r['recommendation']}
        </div>
        ''' for r in report['priority_recommendations'][:10])}
    </div>

    <div class="section">
        <h2>Next Steps</h2>
        {"".join(f'''
        <div class="recommendation">
            <strong>Step {step['step']}: {step['action']}</strong><br>
            {step['description']}<br>
            <em>Timeline: {step['timeline']}</em>
        </div>
        ''' for step in report['next_steps'])}
    </div>

    <div class="cta">
        <h2>Need Help Improving Your Security Posture?</h2>
        <p>Contact VCSO.AI for expert cybersecurity advisory services.</p>
        <p><a href="{config.COMPANY_WEBSITE}">{config.COMPANY_WEBSITE}</a> | <a href="mailto:{config.COMPANY_EMAIL}">{config.COMPANY_EMAIL}</a></p>
    </div>

    <div class="section" style="font-size: 12px; color: #666;">
        <h3>Disclaimer</h3>
        <p>{report['appendix']['disclaimer'].replace(chr(10), '<br>')}</p>
    </div>
</body>
</html>
"""
        return html
