"""
Phishing Simulation Module
Conducts authorized phishing awareness tests
"""

import uuid
import smtplib
import hashlib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from config import config


@dataclass
class PhishingTemplate:
    """Phishing email template"""
    id: str
    name: str
    category: str  # credential_harvest, attachment, link_click, reply
    difficulty: str  # easy, medium, hard
    subject: str
    body_html: str
    body_text: str
    description: str


class PhishingSimulator:
    """Conduct phishing awareness simulations"""

    def __init__(self):
        self.templates = self._load_templates()
        self.smtp_configured = all([
            config.SMTP_HOST,
            config.SMTP_USER,
            config.SMTP_PASSWORD
        ])

    def _load_templates(self) -> List[PhishingTemplate]:
        """Load phishing email templates"""
        return [
            PhishingTemplate(
                id="password_reset",
                name="Password Reset Request",
                category="credential_harvest",
                difficulty="easy",
                subject="Urgent: Your password will expire in 24 hours",
                body_html="""
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <img src="https://via.placeholder.com/150x50?text=IT+Department" alt="IT Department">
                        <h2>Password Expiration Notice</h2>
                        <p>Dear Employee,</p>
                        <p>Our records indicate that your password will expire in <strong>24 hours</strong>.</p>
                        <p>To avoid any disruption to your work, please reset your password immediately by clicking the button below:</p>
                        <p style="text-align: center;">
                            <a href="{{tracking_link}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password Now</a>
                        </p>
                        <p>If you did not request this change, please contact IT support immediately.</p>
                        <p>Best regards,<br>IT Support Team</p>
                    </div>
                </body>
                </html>
                """,
                body_text="""
                Password Expiration Notice

                Dear Employee,

                Our records indicate that your password will expire in 24 hours.

                To avoid any disruption to your work, please reset your password immediately:
                {{tracking_link}}

                If you did not request this change, please contact IT support immediately.

                Best regards,
                IT Support Team
                """,
                description="Classic password expiration phishing - tests basic awareness"
            ),
            PhishingTemplate(
                id="invoice_payment",
                name="Urgent Invoice Payment",
                category="link_click",
                difficulty="medium",
                subject="Invoice #INV-2024-{{random_id}} - Payment Required",
                body_html="""
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2>Invoice Payment Required</h2>
                        <p>Dear Accounts Payable,</p>
                        <p>Please find attached invoice #INV-2024-{{random_id}} for services rendered.</p>
                        <p><strong>Amount Due:</strong> $4,750.00<br>
                        <strong>Due Date:</strong> {{due_date}}</p>
                        <p>Please review and process payment at your earliest convenience:</p>
                        <p><a href="{{tracking_link}}">View Invoice Details</a></p>
                        <p>If you have any questions, please contact our billing department.</p>
                        <p>Best regards,<br>Accounts Receivable<br>ABC Services Inc.</p>
                    </div>
                </body>
                </html>
                """,
                body_text="""
                Invoice Payment Required

                Dear Accounts Payable,

                Please find attached invoice #INV-2024-{{random_id}} for services rendered.

                Amount Due: $4,750.00
                Due Date: {{due_date}}

                View Invoice: {{tracking_link}}

                Best regards,
                Accounts Receivable
                ABC Services Inc.
                """,
                description="Invoice-based phishing - common in BEC attacks"
            ),
            PhishingTemplate(
                id="shared_document",
                name="Shared Document Notification",
                category="credential_harvest",
                difficulty="medium",
                subject="{{sender_name}} shared a document with you",
                body_html="""
                <html>
                <body style="font-family: Arial, sans-serif; background-color: #f5f5f5;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: white;">
                        <div style="text-align: center; padding: 20px;">
                            <img src="https://via.placeholder.com/40x40?text=Doc" alt="Document">
                        </div>
                        <h3 style="text-align: center;">{{sender_name}} shared a file with you</h3>
                        <div style="background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px;">
                            <p style="margin: 0;"><strong>Q3 Financial Report.xlsx</strong></p>
                            <p style="margin: 5px 0 0 0; color: #666; font-size: 12px;">Shared via CloudDocs</p>
                        </div>
                        <p style="text-align: center;">
                            <a href="{{tracking_link}}" style="background-color: #4285f4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Open Document</a>
                        </p>
                        <p style="color: #666; font-size: 12px; text-align: center;">This link will expire in 7 days</p>
                    </div>
                </body>
                </html>
                """,
                body_text="""
                {{sender_name}} shared a file with you

                Q3 Financial Report.xlsx
                Shared via CloudDocs

                Open Document: {{tracking_link}}

                This link will expire in 7 days
                """,
                description="Document sharing phishing - mimics cloud services"
            ),
            PhishingTemplate(
                id="ceo_request",
                name="CEO Wire Transfer Request",
                category="reply",
                difficulty="hard",
                subject="Quick favor needed",
                body_html="""
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <p>Hi,</p>
                    <p>Are you at your desk? I need you to handle something urgent and confidential for me.</p>
                    <p>I'm in a meeting and can't make calls. Can you process a wire transfer today? It's for a time-sensitive acquisition we're closing.</p>
                    <p>Let me know if you can help and I'll send the details.</p>
                    <p>Thanks,<br>{{ceo_name}}</p>
                    <p style="color: #666; font-size: 12px;">Sent from my iPhone</p>
                </body>
                </html>
                """,
                body_text="""
                Hi,

                Are you at your desk? I need you to handle something urgent and confidential for me.

                I'm in a meeting and can't make calls. Can you process a wire transfer today? It's for a time-sensitive acquisition we're closing.

                Let me know if you can help and I'll send the details.

                Thanks,
                {{ceo_name}}

                Sent from my iPhone
                """,
                description="CEO fraud/BEC - tests response to authority"
            ),
            PhishingTemplate(
                id="mfa_verification",
                name="MFA Verification Required",
                category="credential_harvest",
                difficulty="hard",
                subject="Action Required: Verify Your Identity",
                body_html="""
                <html>
                <body style="font-family: Arial, sans-serif;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <div style="background-color: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                            <strong>Security Alert</strong>
                        </div>
                        <p>We detected an unusual sign-in attempt to your account:</p>
                        <table style="width: 100%; margin: 20px 0;">
                            <tr><td><strong>Location:</strong></td><td>{{location}}</td></tr>
                            <tr><td><strong>Device:</strong></td><td>{{device}}</td></tr>
                            <tr><td><strong>Time:</strong></td><td>{{timestamp}}</td></tr>
                        </table>
                        <p>If this was you, please verify your identity to continue:</p>
                        <p style="text-align: center;">
                            <a href="{{tracking_link}}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Yes, This Was Me</a>
                            <a href="{{tracking_link}}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-left: 10px;">No, Secure My Account</a>
                        </p>
                        <p style="color: #666; font-size: 12px;">This is an automated security message. Do not reply.</p>
                    </div>
                </body>
                </html>
                """,
                body_text="""
                Security Alert

                We detected an unusual sign-in attempt to your account:

                Location: {{location}}
                Device: {{device}}
                Time: {{timestamp}}

                If this was you, verify here: {{tracking_link}}

                This is an automated security message.
                """,
                description="MFA fatigue/verification phishing - sophisticated attack"
            )
        ]

    def get_templates(self) -> List[Dict[str, Any]]:
        """Get all available templates"""
        return [
            {
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "difficulty": t.difficulty,
                "description": t.description
            }
            for t in self.templates
        ]

    def get_template(self, template_id: str) -> Optional[PhishingTemplate]:
        """Get a specific template"""
        for t in self.templates:
            if t.id == template_id:
                return t
        return None

    def create_campaign(
        self,
        assessment_id: str,
        emails: List[str],
        template_id: str,
        custom_variables: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """Create a phishing campaign"""
        template = self.get_template(template_id)
        if not template:
            return {"error": "Template not found"}

        campaign_id = str(uuid.uuid4())
        results = []

        for email in emails:
            # Generate unique tracking token
            tracking_token = hashlib.sha256(
                f"{campaign_id}:{email}:{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16]

            # In demo mode, simulate sending
            result = {
                "email": email,
                "tracking_token": tracking_token,
                "template_id": template_id,
                "status": "sent" if self.smtp_configured else "simulated",
                "sent_at": datetime.now().isoformat()
            }

            if self.smtp_configured:
                # Actually send the email
                send_result = self._send_phishing_email(
                    email, template, tracking_token, custom_variables
                )
                result["send_success"] = send_result
            else:
                result["demo_mode"] = True

            results.append(result)

        return {
            "campaign_id": campaign_id,
            "assessment_id": assessment_id,
            "template_used": template_id,
            "total_emails": len(emails),
            "results": results,
            "created_at": datetime.now().isoformat()
        }

    def _send_phishing_email(
        self,
        recipient: str,
        template: PhishingTemplate,
        tracking_token: str,
        custom_variables: Dict[str, str] = None
    ) -> bool:
        """Send a phishing simulation email"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = self._process_template(template.subject, tracking_token, custom_variables)
            msg['From'] = config.SMTP_FROM_EMAIL
            msg['To'] = recipient

            # Process template variables
            text_body = self._process_template(template.body_text, tracking_token, custom_variables)
            html_body = self._process_template(template.body_html, tracking_token, custom_variables)

            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
                server.starttls()
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)

            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

    def _process_template(
        self,
        content: str,
        tracking_token: str,
        custom_variables: Dict[str, str] = None
    ) -> str:
        """Process template variables"""
        variables = {
            "tracking_link": f"https://vcso.ai/phishing-test/{tracking_token}",
            "random_id": str(uuid.uuid4())[:8].upper(),
            "due_date": (datetime.now().replace(day=datetime.now().day + 14)).strftime("%B %d, %Y"),
            "sender_name": "John Smith",
            "ceo_name": "Michael Johnson",
            "location": "Unknown Location (VPN)",
            "device": "Windows PC - Chrome",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        }

        if custom_variables:
            variables.update(custom_variables)

        for key, value in variables.items():
            content = content.replace(f"{{{{{key}}}}}", value)

        return content

    def record_interaction(
        self,
        tracking_token: str,
        interaction_type: str  # opened, clicked, reported
    ) -> Dict[str, Any]:
        """Record phishing test interaction (for webhook handling)"""
        return {
            "tracking_token": tracking_token,
            "interaction_type": interaction_type,
            "timestamp": datetime.now().isoformat()
        }

    def analyze_campaign_results(self, campaign_results: List[Dict]) -> Dict[str, Any]:
        """Analyze phishing campaign results"""
        total = len(campaign_results)
        if total == 0:
            return {"error": "No results to analyze"}

        opened = sum(1 for r in campaign_results if r.get("opened_at"))
        clicked = sum(1 for r in campaign_results if r.get("clicked_at"))
        reported = sum(1 for r in campaign_results if r.get("reported_at"))

        # Calculate risk score (lower is better for phishing)
        click_rate = (clicked / total) * 100 if total > 0 else 0
        risk_score = 100 - click_rate  # Invert so higher is better

        return {
            "total_emails": total,
            "opened": opened,
            "open_rate": round((opened / total) * 100, 1) if total > 0 else 0,
            "clicked": clicked,
            "click_rate": round(click_rate, 1),
            "reported": reported,
            "report_rate": round((reported / total) * 100, 1) if total > 0 else 0,
            "risk_score": round(risk_score, 1),
            "risk_level": self._get_phishing_risk_level(click_rate),
            "recommendations": self._get_phishing_recommendations(click_rate, reported / total if total > 0 else 0)
        }

    def _get_phishing_risk_level(self, click_rate: float) -> str:
        """Determine risk level from click rate"""
        if click_rate <= 5:
            return "LOW"
        elif click_rate <= 15:
            return "MEDIUM"
        elif click_rate <= 30:
            return "HIGH"
        else:
            return "CRITICAL"

    def _get_phishing_recommendations(self, click_rate: float, report_rate: float) -> List[str]:
        """Generate recommendations based on results"""
        recommendations = []

        if click_rate > 20:
            recommendations.append("Implement mandatory security awareness training for all employees")
            recommendations.append("Consider more frequent phishing simulations to build awareness")
        elif click_rate > 10:
            recommendations.append("Provide targeted training for employees who clicked")
            recommendations.append("Review email security gateway settings")
        elif click_rate > 5:
            recommendations.append("Continue regular phishing simulations")
            recommendations.append("Recognize and reward employees who report phishing")

        if report_rate < 0.1:
            recommendations.append("Implement and promote an easy phishing report button")
            recommendations.append("Train employees on how to report suspicious emails")

        if not recommendations:
            recommendations.append("Maintain current security awareness program")
            recommendations.append("Consider more sophisticated phishing scenarios")

        return recommendations

    def simulate_results(self, num_emails: int, template_difficulty: str = "medium") -> Dict[str, Any]:
        """Simulate phishing test results for demo mode"""
        import random

        # Simulate realistic click rates based on difficulty
        base_rates = {
            "easy": {"open": 0.7, "click": 0.35, "report": 0.05},
            "medium": {"open": 0.6, "click": 0.20, "report": 0.08},
            "hard": {"open": 0.5, "click": 0.12, "report": 0.10}
        }

        rates = base_rates.get(template_difficulty, base_rates["medium"])

        # Add some randomness
        opened = int(num_emails * rates["open"] * random.uniform(0.8, 1.2))
        clicked = int(opened * rates["click"] * random.uniform(0.7, 1.3))
        reported = int(num_emails * rates["report"] * random.uniform(0.5, 1.5))

        # Ensure values are within bounds
        opened = min(opened, num_emails)
        clicked = min(clicked, opened)
        reported = min(reported, num_emails)

        return self.analyze_campaign_results([
            {
                "opened_at": datetime.now().isoformat() if i < opened else None,
                "clicked_at": datetime.now().isoformat() if i < clicked else None,
                "reported_at": datetime.now().isoformat() if i < reported else None
            }
            for i in range(num_emails)
        ])
