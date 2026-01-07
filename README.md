# VCSO Security Assessment Platform

A comprehensive cybersecurity assessment platform that provides automated security assessments including SOC2 readiness evaluation, vulnerability scanning, phishing simulations, Git repository security scanning, and dark web monitoring.

## Features

- **SOC2 Type 1 Self-Assessment**: AI-powered questionnaire evaluating organizations against all SOC2 Trust Service Criteria
- **Vulnerability Scanning**: Automated scanning of IP addresses and URLs for security vulnerabilities
- **Phishing Simulation**: Test team security awareness with simulated phishing campaigns
- **Git Repository Scanning**: Scan code repositories for exposed secrets and credentials
- **Dark Web Monitoring**: Check for exposed data in known breaches
- **Comprehensive Reports**: Detailed PDF/HTML reports with prioritized recommendations
- **Security Awareness Training**: Monthly training modules with quizzes and progress tracking
- **Stripe Integration**: One-time assessment payments and monthly training subscriptions

## Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/vcso-security-platform.git
   cd vcso-security-platform
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run the application**
   ```bash
   streamlit run streamlit_app.py
   ```

6. **Access the application**
   Open http://localhost:8501 in your browser

### Deploy to Streamlit Cloud

1. Push your code to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your GitHub repository
4. Add secrets in the Streamlit Cloud dashboard:
   - Go to App Settings > Secrets
   - Add your environment variables

## Configuration

### Required Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `STRIPE_SECRET_KEY` | Stripe secret API key | For payments |
| `STRIPE_PUBLISHABLE_KEY` | Stripe publishable key | For payments |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for AI analysis | None (disabled) |
| `HIBP_API_KEY` | Have I Been Pwned API key | None (simulated) |
| `SMTP_HOST` | SMTP server for phishing emails | None (simulated) |
| `SMTP_PORT` | SMTP port | 587 |
| `SMTP_USER` | SMTP username | None |
| `SMTP_PASSWORD` | SMTP password | None |
| `ASSESSMENT_PRICE` | Assessment price in cents | 29900 ($299) |
| `TRAINING_MONTHLY_PRICE` | Monthly training price in cents | 4900 ($49) |

## Website Integration (vcso.ai)

### Option 1: Embed via iframe

Add this to your website to embed the assessment platform:

```html
<iframe
  src="https://your-app.streamlit.app/?embed=true"
  width="100%"
  height="800"
  frameborder="0"
  style="border: none; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
</iframe>
```

### Option 2: Link Integration

Add a CTA button on your website:

```html
<a href="https://your-app.streamlit.app"
   class="cta-button"
   style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 15px 30px; border-radius: 5px; text-decoration: none; font-weight: bold;">
  Start Your Security Assessment
</a>
```

### Option 3: Subdomain Setup

Deploy to Streamlit Cloud and configure a custom domain:
1. Deploy app to Streamlit Cloud
2. Go to App Settings > Custom domain
3. Add CNAME record: `assess.vcso.ai` → `your-app.streamlit.app`

## Architecture

```
vcso-security-platform/
├── streamlit_app.py          # Main Streamlit application
├── config.py                 # Configuration settings
├── database.py               # SQLite database operations
├── requirements.txt          # Python dependencies
├── modules/
│   ├── stripe_integration.py # Payment processing
│   ├── soc2_assessment.py    # SOC2 questionnaire engine
│   ├── vulnerability_scanner.py # IP/URL scanning
│   ├── phishing_simulator.py # Phishing campaigns
│   ├── git_scanner.py        # Repository scanning
│   ├── dark_web_scanner.py   # Breach monitoring
│   ├── report_generator.py   # Report creation
│   └── training.py           # Training modules
└── data/
    └── vcso_platform.db      # SQLite database (auto-created)
```

## Security Modules

### SOC2 Assessment
- 27 questions covering all Trust Service Criteria
- Categories: Security (CC), Availability (A), Processing Integrity (PI), Confidentiality (C), Privacy (P)
- Weighted scoring with risk level determination
- AI-powered recommendations (when OpenAI configured)

### Vulnerability Scanner
- Port scanning for common services (FTP, SSH, HTTP, databases, etc.)
- Detection of dangerous exposed ports
- SSL/TLS certificate validation
- Security header analysis
- Sensitive file exposure checks

### Phishing Simulator
- 5 pre-built phishing templates (easy to hard difficulty)
- Template categories: credential harvest, link click, BEC fraud
- Campaign tracking and analytics
- Risk scoring based on click rates

### Git Scanner
- Secret detection (AWS keys, API tokens, passwords, private keys)
- Dangerous file detection (.env, credentials, etc.)
- Security configuration analysis
- Dependency vulnerability checks

### Dark Web Scanner
- Integration with Have I Been Pwned API
- Domain breach monitoring
- Email exposure checking
- Password breach verification (using k-anonymity)

## Demo Mode

The platform runs in demo mode when external APIs are not configured:
- **Payments**: Simulated checkout flow
- **Phishing**: Simulated campaign results
- **Dark Web**: Simulated breach data
- **Git Scanning**: Simulated repository analysis

## Customization

### Pricing
Update in `.env` or `config.py`:
```python
ASSESSMENT_PRICE = 29900  # $299.00
TRAINING_MONTHLY_PRICE = 4900  # $49.00/month
```

### Branding
Update in `config.py`:
```python
COMPANY_NAME = "VCSO.AI"
COMPANY_WEBSITE = "https://www.vcso.ai"
COMPANY_EMAIL = "contact@vcso.ai"
```

### Adding SOC2 Questions
Edit `modules/soc2_assessment.py` and add to the `questions_data` list.

### Adding Training Modules
Edit `modules/training.py` and add to the `modules_data` list.

## Stripe Webhook Setup

For production, configure Stripe webhooks to handle:
1. `checkout.session.completed` - Payment success
2. `customer.subscription.updated` - Subscription changes
3. `customer.subscription.deleted` - Cancellations

Webhook endpoint: `https://your-app.streamlit.app/api/stripe-webhook`

## Support

For issues and feature requests, contact: contact@vcso.ai

Website: https://www.vcso.ai

## License

MIT License - See LICENSE file for details.
