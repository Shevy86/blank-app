"""
VCSO Security Assessment Platform Configuration

Environment variables should be set for production use.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    """Application configuration"""

    # Application Settings
    APP_NAME: str = "VCSO Security Assessment Platform"
    APP_VERSION: str = "1.0.0"
    COMPANY_NAME: str = "VCSO.AI"
    COMPANY_WEBSITE: str = "https://www.vcso.ai"
    COMPANY_EMAIL: str = "contact@vcso.ai"

    # Database
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "data/vcso_platform.db")

    # Stripe Configuration
    STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_PUBLISHABLE_KEY: str = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
    STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")

    # Pricing (in cents)
    ASSESSMENT_PRICE: int = int(os.getenv("ASSESSMENT_PRICE", "29900"))  # $299.00
    TRAINING_MONTHLY_PRICE: int = int(os.getenv("TRAINING_MONTHLY_PRICE", "4900"))  # $49.00/month

    # OpenAI Configuration (for AI-powered assessment)
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # Email Configuration (for phishing tests)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "security-test@vcso.ai")

    # Dark Web Monitoring API (e.g., Have I Been Pwned, SpyCloud)
    HIBP_API_KEY: str = os.getenv("HIBP_API_KEY", "")

    # Security Settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-this-in-production-vcso-2024")

    # Scanning Limits
    MAX_IPS_PER_SCAN: int = 10
    MAX_URLS_PER_SCAN: int = 20
    MAX_EMAILS_PER_PHISHING_TEST: int = 50
    MAX_REPOS_PER_SCAN: int = 5

    # Report Settings
    REPORT_RETENTION_DAYS: int = 90

    @classmethod
    def get_instance(cls) -> 'Config':
        """Get singleton config instance"""
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
        return cls._instance


# SOC2 Trust Service Criteria Categories
SOC2_CATEGORIES = {
    "CC": "Common Criteria (Security)",
    "A": "Availability",
    "PI": "Processing Integrity",
    "C": "Confidentiality",
    "P": "Privacy"
}

# Risk Levels
RISK_LEVELS = {
    "CRITICAL": {"score": 0, "color": "#dc3545", "label": "Critical"},
    "HIGH": {"score": 25, "color": "#fd7e14", "label": "High"},
    "MEDIUM": {"score": 50, "color": "#ffc107", "label": "Medium"},
    "LOW": {"score": 75, "color": "#28a745", "label": "Low"},
    "MINIMAL": {"score": 90, "color": "#20c997", "label": "Minimal"}
}

# Legal Disclaimers
LEGAL_DISCLAIMERS = {
    "assessment_disclaimer": """
## Security Assessment Disclaimer

By proceeding with this security assessment, you acknowledge and agree to the following:

1. **Authorization**: You confirm that you have proper authorization to conduct security assessments on the systems, networks, IP addresses, URLs, email addresses, and repositories you provide.

2. **Scope Limitations**: This assessment provides a point-in-time snapshot and may not identify all vulnerabilities. It should be used as part of a comprehensive security program.

3. **No Guarantee**: VCSO.AI makes no guarantees regarding the completeness or accuracy of the assessment results. Security threats evolve continuously.

4. **Data Handling**: Information collected during this assessment will be handled in accordance with our Privacy Policy. Assessment data is retained for {retention_days} days.

5. **Liability Limitation**: VCSO.AI shall not be liable for any damages arising from the use of this assessment tool or its results.

6. **Professional Advice**: This tool does not replace professional security consulting. For comprehensive security guidance, please contact VCSO.AI directly.

7. **Compliance**: This assessment is designed to help identify potential gaps but does not constitute SOC2 certification or formal compliance attestation.
""",

    "phishing_disclaimer": """
## Phishing Simulation Consent

By initiating a phishing simulation test, you confirm:

1. **Employee Notification**: You have the authority to conduct phishing awareness tests on the email addresses provided.

2. **No Malicious Intent**: These simulations are for security awareness purposes only.

3. **Data Privacy**: Email addresses and test results will be handled confidentially.

4. **Opt-Out Compliance**: You will honor any opt-out requests from test recipients.
""",

    "subscription_terms": """
## Training Subscription Terms

1. **Billing**: Your subscription will be billed monthly on the anniversary of your signup date.

2. **Cancellation**: You may cancel at any time. Access continues until the end of the billing period.

3. **Content Updates**: Training content is updated regularly to reflect current threats.

4. **License**: Training materials are licensed for use by employees of your organization only.

5. **Refunds**: Refunds are available within 14 days of initial purchase if training has not been accessed.
"""
}

config = Config.get_instance()
