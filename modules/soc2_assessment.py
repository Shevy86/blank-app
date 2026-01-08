"""
SOC2 Type 1 AI-Powered Self-Assessment Module
Evaluates organization's security posture against SOC2 Trust Service Criteria
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from config import config, SOC2_CATEGORIES


@dataclass
class AssessmentQuestion:
    """Represents a SOC2 assessment question"""
    id: str
    category: str
    subcategory: str
    question: str
    description: str
    weight: float
    options: List[Dict[str, Any]]


class SOC2Assessment:
    """AI-powered SOC2 Type 1 self-assessment"""

    def __init__(self):
        self.questions = self._load_questions()
        self.openai_configured = bool(config.OPENAI_API_KEY)

    def _load_questions(self) -> List[AssessmentQuestion]:
        """Load SOC2 assessment questions"""
        # Comprehensive SOC2 Type 1 questions covering all Trust Service Criteria
        questions_data = [
            # CC1 - Control Environment
            {
                "id": "CC1.1",
                "category": "CC",
                "subcategory": "Control Environment",
                "question": "Does your organization have a documented information security policy?",
                "description": "A formal security policy establishes the foundation for your security program.",
                "weight": 1.0,
                "options": [
                    {"value": "yes_comprehensive", "label": "Yes, comprehensive and regularly updated", "score": 100},
                    {"value": "yes_basic", "label": "Yes, but needs updating", "score": 60},
                    {"value": "in_progress", "label": "Currently developing one", "score": 30},
                    {"value": "no", "label": "No formal policy exists", "score": 0}
                ]
            },
            {
                "id": "CC1.2",
                "category": "CC",
                "subcategory": "Control Environment",
                "question": "Is there a designated individual or team responsible for information security?",
                "description": "Clear ownership ensures accountability for security initiatives.",
                "weight": 1.0,
                "options": [
                    {"value": "dedicated_team", "label": "Dedicated security team/CISO", "score": 100},
                    {"value": "designated_person", "label": "Designated security officer (part-time)", "score": 70},
                    {"value": "it_responsibility", "label": "IT handles security among other duties", "score": 40},
                    {"value": "no_ownership", "label": "No clear ownership", "score": 0}
                ]
            },
            {
                "id": "CC1.3",
                "category": "CC",
                "subcategory": "Control Environment",
                "question": "Does your organization conduct background checks on employees?",
                "description": "Background checks help verify the integrity of personnel with access to systems.",
                "weight": 0.8,
                "options": [
                    {"value": "all_employees", "label": "Yes, for all employees", "score": 100},
                    {"value": "sensitive_roles", "label": "Yes, for sensitive roles only", "score": 70},
                    {"value": "sometimes", "label": "Sometimes, inconsistently", "score": 30},
                    {"value": "no", "label": "No background checks", "score": 0}
                ]
            },

            # CC2 - Communication and Information
            {
                "id": "CC2.1",
                "category": "CC",
                "subcategory": "Communication and Information",
                "question": "Do you have a process for communicating security policies to employees?",
                "description": "Employees must understand their security responsibilities.",
                "weight": 0.9,
                "options": [
                    {"value": "formal_training", "label": "Formal onboarding and regular training", "score": 100},
                    {"value": "onboarding_only", "label": "During onboarding only", "score": 50},
                    {"value": "informal", "label": "Informal communication", "score": 25},
                    {"value": "none", "label": "No formal communication", "score": 0}
                ]
            },
            {
                "id": "CC2.2",
                "category": "CC",
                "subcategory": "Communication and Information",
                "question": "Is there a process for reporting security incidents internally?",
                "description": "Clear reporting channels enable quick response to security events.",
                "weight": 1.0,
                "options": [
                    {"value": "formal_process", "label": "Formal incident reporting process with tracking", "score": 100},
                    {"value": "email_reporting", "label": "Email-based reporting", "score": 60},
                    {"value": "informal", "label": "Informal verbal reporting", "score": 30},
                    {"value": "none", "label": "No defined process", "score": 0}
                ]
            },

            # CC3 - Risk Assessment
            {
                "id": "CC3.1",
                "category": "CC",
                "subcategory": "Risk Assessment",
                "question": "Does your organization conduct regular risk assessments?",
                "description": "Risk assessments identify and prioritize security threats.",
                "weight": 1.0,
                "options": [
                    {"value": "annual_formal", "label": "Annual formal risk assessment", "score": 100},
                    {"value": "periodic_informal", "label": "Periodic informal assessments", "score": 50},
                    {"value": "ad_hoc", "label": "Ad-hoc when issues arise", "score": 25},
                    {"value": "never", "label": "No risk assessments conducted", "score": 0}
                ]
            },
            {
                "id": "CC3.2",
                "category": "CC",
                "subcategory": "Risk Assessment",
                "question": "Do you maintain an inventory of information assets?",
                "description": "Asset inventory is essential for protecting what matters.",
                "weight": 0.9,
                "options": [
                    {"value": "comprehensive", "label": "Comprehensive and regularly updated", "score": 100},
                    {"value": "partial", "label": "Partial inventory exists", "score": 50},
                    {"value": "outdated", "label": "Exists but outdated", "score": 25},
                    {"value": "none", "label": "No asset inventory", "score": 0}
                ]
            },

            # CC4 - Monitoring Activities
            {
                "id": "CC4.1",
                "category": "CC",
                "subcategory": "Monitoring Activities",
                "question": "Do you monitor systems for security events?",
                "description": "Continuous monitoring helps detect threats early.",
                "weight": 1.0,
                "options": [
                    {"value": "siem_247", "label": "SIEM with 24/7 monitoring", "score": 100},
                    {"value": "logging_review", "label": "Logging with periodic review", "score": 60},
                    {"value": "basic_logging", "label": "Basic logging, rarely reviewed", "score": 30},
                    {"value": "none", "label": "No security monitoring", "score": 0}
                ]
            },
            {
                "id": "CC4.2",
                "category": "CC",
                "subcategory": "Monitoring Activities",
                "question": "Do you conduct internal audits of security controls?",
                "description": "Internal audits verify that controls are operating effectively.",
                "weight": 0.8,
                "options": [
                    {"value": "regular", "label": "Regular internal audits (at least annually)", "score": 100},
                    {"value": "occasional", "label": "Occasional audits", "score": 50},
                    {"value": "external_only", "label": "External audits only", "score": 40},
                    {"value": "none", "label": "No security audits", "score": 0}
                ]
            },

            # CC5 - Control Activities
            {
                "id": "CC5.1",
                "category": "CC",
                "subcategory": "Control Activities",
                "question": "Is multi-factor authentication (MFA) required for system access?",
                "description": "MFA significantly reduces the risk of unauthorized access.",
                "weight": 1.0,
                "options": [
                    {"value": "all_systems", "label": "Required for all systems", "score": 100},
                    {"value": "critical_systems", "label": "Required for critical systems only", "score": 70},
                    {"value": "optional", "label": "Available but optional", "score": 30},
                    {"value": "none", "label": "Not implemented", "score": 0}
                ]
            },
            {
                "id": "CC5.2",
                "category": "CC",
                "subcategory": "Control Activities",
                "question": "How is access to sensitive systems managed?",
                "description": "Proper access control limits exposure to sensitive data.",
                "weight": 1.0,
                "options": [
                    {"value": "rbac_reviewed", "label": "Role-based access with regular reviews", "score": 100},
                    {"value": "rbac_no_review", "label": "Role-based access, no regular reviews", "score": 60},
                    {"value": "basic", "label": "Basic user/admin roles only", "score": 30},
                    {"value": "none", "label": "No formal access management", "score": 0}
                ]
            },
            {
                "id": "CC5.3",
                "category": "CC",
                "subcategory": "Control Activities",
                "question": "Is data encrypted at rest and in transit?",
                "description": "Encryption protects data from unauthorized access.",
                "weight": 1.0,
                "options": [
                    {"value": "both", "label": "Yes, both at rest and in transit", "score": 100},
                    {"value": "transit_only", "label": "In transit only (HTTPS/TLS)", "score": 50},
                    {"value": "partial", "label": "Partial encryption", "score": 30},
                    {"value": "none", "label": "No encryption", "score": 0}
                ]
            },

            # CC6 - Logical and Physical Access Controls
            {
                "id": "CC6.1",
                "category": "CC",
                "subcategory": "Logical and Physical Access",
                "question": "How are passwords managed in your organization?",
                "description": "Strong password policies prevent credential-based attacks.",
                "weight": 0.9,
                "options": [
                    {"value": "password_manager", "label": "Enterprise password manager with strong policy", "score": 100},
                    {"value": "strong_policy", "label": "Strong password policy enforced", "score": 70},
                    {"value": "basic_policy", "label": "Basic password requirements", "score": 40},
                    {"value": "no_policy", "label": "No password policy", "score": 0}
                ]
            },
            {
                "id": "CC6.2",
                "category": "CC",
                "subcategory": "Logical and Physical Access",
                "question": "Is there a process for revoking access when employees leave?",
                "description": "Timely access revocation prevents unauthorized access by former employees.",
                "weight": 1.0,
                "options": [
                    {"value": "immediate_automated", "label": "Immediate, automated deprovisioning", "score": 100},
                    {"value": "same_day", "label": "Same-day manual deprovisioning", "score": 80},
                    {"value": "within_week", "label": "Within a week", "score": 40},
                    {"value": "no_process", "label": "No formal process", "score": 0}
                ]
            },

            # CC7 - System Operations
            {
                "id": "CC7.1",
                "category": "CC",
                "subcategory": "System Operations",
                "question": "How is vulnerability management handled?",
                "description": "Regular patching and vulnerability management reduce attack surface.",
                "weight": 1.0,
                "options": [
                    {"value": "automated_scanning", "label": "Automated scanning with defined SLAs", "score": 100},
                    {"value": "periodic_scanning", "label": "Periodic vulnerability scanning", "score": 60},
                    {"value": "manual_patching", "label": "Manual patching when notified", "score": 30},
                    {"value": "none", "label": "No vulnerability management", "score": 0}
                ]
            },
            {
                "id": "CC7.2",
                "category": "CC",
                "subcategory": "System Operations",
                "question": "Do you have an incident response plan?",
                "description": "A documented incident response plan enables effective handling of security events.",
                "weight": 1.0,
                "options": [
                    {"value": "documented_tested", "label": "Documented and regularly tested", "score": 100},
                    {"value": "documented", "label": "Documented but not tested", "score": 60},
                    {"value": "informal", "label": "Informal process", "score": 30},
                    {"value": "none", "label": "No incident response plan", "score": 0}
                ]
            },

            # CC8 - Change Management
            {
                "id": "CC8.1",
                "category": "CC",
                "subcategory": "Change Management",
                "question": "Is there a formal change management process?",
                "description": "Change management prevents unauthorized or untested changes to systems.",
                "weight": 0.9,
                "options": [
                    {"value": "formal_approval", "label": "Formal process with approval workflow", "score": 100},
                    {"value": "documented", "label": "Documented process, informal approval", "score": 60},
                    {"value": "informal", "label": "Informal process", "score": 30},
                    {"value": "none", "label": "No change management", "score": 0}
                ]
            },

            # CC9 - Risk Mitigation
            {
                "id": "CC9.1",
                "category": "CC",
                "subcategory": "Risk Mitigation",
                "question": "Do you have cyber insurance coverage?",
                "description": "Cyber insurance helps mitigate financial impact of security incidents.",
                "weight": 0.7,
                "options": [
                    {"value": "comprehensive", "label": "Comprehensive cyber insurance", "score": 100},
                    {"value": "basic", "label": "Basic cyber insurance", "score": 70},
                    {"value": "considering", "label": "Evaluating options", "score": 30},
                    {"value": "none", "label": "No cyber insurance", "score": 0}
                ]
            },

            # Availability
            {
                "id": "A1.1",
                "category": "A",
                "subcategory": "Availability",
                "question": "Do you have documented backup and recovery procedures?",
                "description": "Backup procedures ensure business continuity in case of data loss.",
                "weight": 1.0,
                "options": [
                    {"value": "tested_regularly", "label": "Documented and tested regularly", "score": 100},
                    {"value": "documented", "label": "Documented but rarely tested", "score": 60},
                    {"value": "informal", "label": "Informal backup process", "score": 30},
                    {"value": "none", "label": "No backup procedures", "score": 0}
                ]
            },
            {
                "id": "A1.2",
                "category": "A",
                "subcategory": "Availability",
                "question": "Do you have a disaster recovery plan?",
                "description": "DR plans ensure systems can be restored after major incidents.",
                "weight": 1.0,
                "options": [
                    {"value": "comprehensive_tested", "label": "Comprehensive plan, tested annually", "score": 100},
                    {"value": "documented", "label": "Documented but not tested", "score": 50},
                    {"value": "informal", "label": "Informal understanding", "score": 25},
                    {"value": "none", "label": "No disaster recovery plan", "score": 0}
                ]
            },

            # Confidentiality
            {
                "id": "C1.1",
                "category": "C",
                "subcategory": "Confidentiality",
                "question": "How is confidential data classified and handled?",
                "description": "Data classification enables appropriate protection based on sensitivity.",
                "weight": 1.0,
                "options": [
                    {"value": "formal_classification", "label": "Formal data classification scheme", "score": 100},
                    {"value": "basic_categories", "label": "Basic categories (public/private)", "score": 50},
                    {"value": "informal", "label": "Informal understanding", "score": 25},
                    {"value": "none", "label": "No data classification", "score": 0}
                ]
            },
            {
                "id": "C1.2",
                "category": "C",
                "subcategory": "Confidentiality",
                "question": "Do you have data retention and disposal policies?",
                "description": "Proper data lifecycle management reduces risk exposure.",
                "weight": 0.8,
                "options": [
                    {"value": "formal_policy", "label": "Formal policy with secure disposal", "score": 100},
                    {"value": "basic_policy", "label": "Basic retention policy", "score": 60},
                    {"value": "informal", "label": "Informal guidelines", "score": 30},
                    {"value": "none", "label": "No retention/disposal policy", "score": 0}
                ]
            },

            # Privacy
            {
                "id": "P1.1",
                "category": "P",
                "subcategory": "Privacy",
                "question": "Do you have a privacy policy communicated to customers?",
                "description": "Privacy policies inform users how their data is handled.",
                "weight": 1.0,
                "options": [
                    {"value": "comprehensive", "label": "Comprehensive, regularly updated", "score": 100},
                    {"value": "basic", "label": "Basic privacy policy", "score": 60},
                    {"value": "outdated", "label": "Exists but outdated", "score": 30},
                    {"value": "none", "label": "No privacy policy", "score": 0}
                ]
            },
            {
                "id": "P1.2",
                "category": "P",
                "subcategory": "Privacy",
                "question": "Is there a process for handling data subject requests (DSARs)?",
                "description": "DSAR processes ensure compliance with privacy regulations.",
                "weight": 0.9,
                "options": [
                    {"value": "formal_process", "label": "Formal documented process", "score": 100},
                    {"value": "informal_process", "label": "Informal process", "score": 50},
                    {"value": "ad_hoc", "label": "Handled ad-hoc", "score": 25},
                    {"value": "none", "label": "No DSAR process", "score": 0}
                ]
            },

            # Processing Integrity
            {
                "id": "PI1.1",
                "category": "PI",
                "subcategory": "Processing Integrity",
                "question": "Are system inputs validated for accuracy and completeness?",
                "description": "Input validation prevents errors and security vulnerabilities.",
                "weight": 0.9,
                "options": [
                    {"value": "comprehensive", "label": "Comprehensive validation with logging", "score": 100},
                    {"value": "basic", "label": "Basic input validation", "score": 60},
                    {"value": "minimal", "label": "Minimal validation", "score": 30},
                    {"value": "none", "label": "No input validation", "score": 0}
                ]
            },
            {
                "id": "PI1.2",
                "category": "PI",
                "subcategory": "Processing Integrity",
                "question": "Do you have quality assurance processes for system outputs?",
                "description": "QA processes ensure system outputs are accurate and complete.",
                "weight": 0.8,
                "options": [
                    {"value": "formal_qa", "label": "Formal QA process", "score": 100},
                    {"value": "spot_checks", "label": "Periodic spot checks", "score": 50},
                    {"value": "user_reported", "label": "Rely on user-reported issues", "score": 25},
                    {"value": "none", "label": "No QA process", "score": 0}
                ]
            }
        ]

        return [AssessmentQuestion(**q) for q in questions_data]

    def get_questions(self) -> List[Dict[str, Any]]:
        """Get all questions as dictionaries"""
        return [
            {
                "id": q.id,
                "category": q.category,
                "category_name": SOC2_CATEGORIES.get(q.category, q.category),
                "subcategory": q.subcategory,
                "question": q.question,
                "description": q.description,
                "weight": q.weight,
                "options": q.options
            }
            for q in self.questions
        ]

    def get_questions_by_category(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get questions grouped by category"""
        grouped = {}
        for q in self.get_questions():
            cat = q["category"]
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(q)
        return grouped

    def calculate_score(self, responses: Dict[str, str]) -> Dict[str, Any]:
        """Calculate overall score from responses"""
        total_weighted_score = 0
        total_weight = 0
        category_scores = {}

        for question in self.questions:
            if question.id in responses:
                response = responses[question.id]
                # Find the score for the selected option
                for option in question.options:
                    if option["value"] == response:
                        score = option["score"]
                        weighted_score = score * question.weight
                        total_weighted_score += weighted_score
                        total_weight += question.weight

                        # Track category scores
                        cat = question.category
                        if cat not in category_scores:
                            category_scores[cat] = {"total": 0, "weight": 0}
                        category_scores[cat]["total"] += weighted_score
                        category_scores[cat]["weight"] += question.weight
                        break

        overall_score = (total_weighted_score / total_weight * 100) if total_weight > 0 else 0

        # Calculate category scores
        for cat in category_scores:
            if category_scores[cat]["weight"] > 0:
                category_scores[cat]["score"] = (
                    category_scores[cat]["total"] / category_scores[cat]["weight"]
                )
            else:
                category_scores[cat]["score"] = 0

        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)

        return {
            "overall_score": round(overall_score, 1),
            "risk_level": risk_level,
            "category_scores": {
                cat: round(data["score"], 1)
                for cat, data in category_scores.items()
            },
            "questions_answered": len(responses),
            "total_questions": len(self.questions)
        }

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score"""
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

    def generate_recommendations(self, responses: Dict[str, str]) -> List[Dict[str, Any]]:
        """Generate recommendations based on responses"""
        recommendations = []

        for question in self.questions:
            if question.id in responses:
                response = responses[question.id]
                for option in question.options:
                    if option["value"] == response and option["score"] < 70:
                        recommendations.append({
                            "question_id": question.id,
                            "category": question.category,
                            "subcategory": question.subcategory,
                            "current_state": option["label"],
                            "score": option["score"],
                            "question": question.question,
                            "recommendation": self._get_recommendation(question, option),
                            "priority": "High" if option["score"] < 30 else "Medium"
                        })
                        break

        # Sort by priority
        recommendations.sort(key=lambda x: (0 if x["priority"] == "High" else 1, x["score"]))
        return recommendations

    def _get_recommendation(self, question: AssessmentQuestion, current_option: Dict) -> str:
        """Generate specific recommendation for a low-scoring answer"""
        # Find the best option
        best_option = max(question.options, key=lambda x: x["score"])

        recommendation_templates = {
            "CC1.1": "Develop and document a comprehensive information security policy. Review and update it annually.",
            "CC1.2": "Designate a security officer or team with clear responsibilities for information security.",
            "CC1.3": "Implement background check procedures for all employees, especially those with access to sensitive systems.",
            "CC2.1": "Establish a formal security awareness training program with regular updates.",
            "CC2.2": "Implement a formal incident reporting system with tracking and escalation procedures.",
            "CC3.1": "Conduct formal risk assessments at least annually, documenting findings and remediation plans.",
            "CC3.2": "Create and maintain a comprehensive inventory of all information assets.",
            "CC4.1": "Implement centralized logging and consider a SIEM solution for security monitoring.",
            "CC4.2": "Establish an internal audit program to regularly assess security control effectiveness.",
            "CC5.1": "Deploy multi-factor authentication across all systems, prioritizing critical applications.",
            "CC5.2": "Implement role-based access control with quarterly access reviews.",
            "CC5.3": "Enable encryption for data at rest and in transit using industry-standard protocols.",
            "CC6.1": "Deploy an enterprise password manager and enforce strong password policies.",
            "CC6.2": "Automate user deprovisioning to ensure immediate access revocation upon termination.",
            "CC7.1": "Implement automated vulnerability scanning with defined SLAs for remediation.",
            "CC7.2": "Document and regularly test your incident response plan.",
            "CC8.1": "Implement a formal change management process with approval workflows.",
            "CC9.1": "Evaluate and obtain appropriate cyber insurance coverage.",
            "A1.1": "Document and regularly test backup and recovery procedures.",
            "A1.2": "Develop and annually test a comprehensive disaster recovery plan.",
            "C1.1": "Implement a formal data classification scheme and handling procedures.",
            "C1.2": "Document data retention periods and secure disposal procedures.",
            "P1.1": "Review and update your privacy policy to reflect current practices.",
            "P1.2": "Implement a formal process for handling data subject access requests.",
            "PI1.1": "Implement comprehensive input validation across all systems.",
            "PI1.2": "Establish quality assurance processes to verify system output accuracy."
        }

        return recommendation_templates.get(
            question.id,
            f"Improve from '{current_option['label']}' to '{best_option['label']}' for better security posture."
        )

    def analyze_with_ai(self, responses: Dict[str, str], company_context: str = "") -> Optional[str]:
        """Use AI to provide detailed analysis (if configured)"""
        if not self.openai_configured:
            return None

        try:
            import openai
            openai.api_key = config.OPENAI_API_KEY

            # Build context
            response_summary = []
            for question in self.questions:
                if question.id in responses:
                    response = responses[question.id]
                    for option in question.options:
                        if option["value"] == response:
                            response_summary.append(f"- {question.question}: {option['label']}")
                            break

            prompt = f"""Analyze this SOC2 Type 1 self-assessment and provide actionable recommendations:

Company Context: {company_context or 'Not provided'}

Assessment Responses:
{chr(10).join(response_summary)}

Provide:
1. Executive summary of security posture
2. Top 5 priority recommendations
3. Quick wins that can be implemented immediately
4. Long-term strategic improvements needed

Format the response in clear sections."""

            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a SOC2 compliance expert providing actionable security recommendations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1500
            )

            return response.choices[0].message.content

        except Exception as e:
            print(f"AI analysis error: {e}")
            return None
