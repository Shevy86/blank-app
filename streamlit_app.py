"""
VCSO Security Assessment Platform
Main Streamlit Application
"""

import streamlit as st
from datetime import datetime
import json

# Page configuration
st.set_page_config(
    page_title="VCSO Security Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize database
from database import init_database
init_database()

# Import modules
from config import config, LEGAL_DISCLAIMERS
from modules.stripe_integration import StripeIntegration
from modules.soc2_assessment import SOC2Assessment
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.phishing_simulator import PhishingSimulator
from modules.git_scanner import GitScanner
from modules.dark_web_scanner import DarkWebScanner
from modules.report_generator import ReportGenerator
from modules.training import TrainingManager
import database as db

# Initialize services
stripe_service = StripeIntegration()
soc2_service = SOC2Assessment()
vuln_scanner = VulnerabilityScanner()
phishing_service = PhishingSimulator()
git_scanner = GitScanner()
dark_web_scanner = DarkWebScanner()
report_generator = ReportGenerator()
training_manager = TrainingManager()

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        margin-bottom: 2rem;
    }
    .main-header h1 {
        color: white;
        margin-bottom: 0.5rem;
    }
    .score-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        text-align: center;
        margin: 0.5rem;
    }
    .score-value {
        font-size: 3rem;
        font-weight: bold;
    }
    .score-critical { color: #dc3545; }
    .score-high { color: #fd7e14; }
    .score-medium { color: #ffc107; }
    .score-low { color: #28a745; }
    .score-minimal { color: #20c997; }
    .feature-card {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        border-left: 4px solid #16213e;
    }
    .price-tag {
        background: #16213e;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: bold;
    }
    .cta-button {
        background: linear-gradient(135deg, #4da6ff 0%, #16213e 100%);
        color: white;
        padding: 1rem 2rem;
        border-radius: 5px;
        text-decoration: none;
        display: inline-block;
    }
    .disclaimer-box {
        background: #fff3cd;
        border: 1px solid #ffc107;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .step-indicator {
        display: flex;
        justify-content: space-between;
        margin-bottom: 2rem;
    }
    .step {
        text-align: center;
        flex: 1;
        padding: 1rem;
        position: relative;
    }
    .step.active {
        background: #e7f3ff;
        border-radius: 10px;
    }
    .step.completed {
        background: #d4edda;
        border-radius: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'user' not in st.session_state:
    st.session_state.user = None
if 'assessment_id' not in st.session_state:
    st.session_state.assessment_id = None
if 'current_step' not in st.session_state:
    st.session_state.current_step = 'welcome'
if 'disclaimers_accepted' not in st.session_state:
    st.session_state.disclaimers_accepted = False
if 'payment_complete' not in st.session_state:
    st.session_state.payment_complete = False
if 'assessment_results' not in st.session_state:
    st.session_state.assessment_results = {}


def show_welcome_page():
    """Display the welcome/landing page"""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ VCSO Security Assessment Platform</h1>
        <p>Comprehensive cybersecurity assessment powered by AI</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("## What's Included in Your Assessment")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div class="feature-card">
            <h3>📋 SOC2 Type 1 Self-Assessment</h3>
            <p>AI-powered questionnaire evaluating your organization against all SOC2 Trust Service Criteria.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <h3>🔍 Vulnerability Scan</h3>
            <p>Automated scanning of your IP addresses and URLs for security vulnerabilities and misconfigurations.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <h3>🎣 Phishing Simulation</h3>
            <p>Test your team's security awareness with simulated phishing campaigns.</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="feature-card">
            <h3>📦 Git Repository Scan</h3>
            <p>Scan your code repositories for exposed secrets, credentials, and security issues.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <h3>🌐 Dark Web Monitoring</h3>
            <p>Check if your organization's data has been exposed in known data breaches.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <h3>📊 Comprehensive Report</h3>
            <p>Detailed security report with prioritized recommendations and remediation guidance.</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Pricing
    st.markdown("## Pricing")

    col1, col2 = st.columns(2)

    prices = stripe_service.get_price_display()

    with col1:
        st.markdown(f"""
        <div class="score-card">
            <h3>One-Time Assessment</h3>
            <div class="score-value score-low">{prices['assessment']}</div>
            <ul style="text-align: left;">
                <li>Complete security assessment</li>
                <li>SOC2 readiness evaluation</li>
                <li>Vulnerability scanning</li>
                <li>Phishing simulation</li>
                <li>Git repository scan</li>
                <li>Dark web monitoring</li>
                <li>Comprehensive PDF report</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="score-card">
            <h3>Training Subscription</h3>
            <div class="score-value score-low">{prices['training_monthly']}</div>
            <ul style="text-align: left;">
                <li>Monthly security awareness training</li>
                <li>Phishing simulation campaigns</li>
                <li>Progress tracking dashboard</li>
                <li>Quiz and certification</li>
                <li>New content updates</li>
                <li>Cancel anytime</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Start Assessment Button
    st.markdown("## Ready to Get Started?")

    if st.button("🚀 Start Your Security Assessment", type="primary", use_container_width=True):
        st.session_state.current_step = 'registration'
        st.rerun()


def show_registration_page():
    """Display the registration page"""
    st.markdown("## Step 1: Company Information")

    with st.form("registration_form"):
        col1, col2 = st.columns(2)

        with col1:
            email = st.text_input("Email Address *", placeholder="you@company.com")
            company_name = st.text_input("Company Name *", placeholder="Acme Inc.")

        with col2:
            contact_name = st.text_input("Your Name", placeholder="John Smith")
            company_website = st.text_input("Company Website", placeholder="https://www.company.com")

        st.markdown("---")

        st.markdown("### Assessment Scope")

        col1, col2 = st.columns(2)

        with col1:
            ip_addresses = st.text_area(
                "IP Addresses to Scan (one per line)",
                placeholder="203.0.113.1\n203.0.113.2",
                help=f"Maximum {config.MAX_IPS_PER_SCAN} IP addresses"
            )

            urls = st.text_area(
                "URLs to Scan (one per line)",
                placeholder="https://www.company.com\nhttps://app.company.com",
                help=f"Maximum {config.MAX_URLS_PER_SCAN} URLs"
            )

        with col2:
            emails_to_test = st.text_area(
                "Employee Emails for Phishing Test (one per line)",
                placeholder="employee1@company.com\nemployee2@company.com",
                help=f"Maximum {config.MAX_EMAILS_PER_PHISHING_TEST} email addresses"
            )

            git_repos = st.text_area(
                "Git Repository URLs (one per line)",
                placeholder="https://github.com/company/repo",
                help=f"Maximum {config.MAX_REPOS_PER_SCAN} repositories. Public repos only."
            )

        domain_for_dark_web = st.text_input(
            "Domain for Dark Web Monitoring",
            placeholder="company.com",
            help="We'll check if your domain appears in known data breaches"
        )

        submitted = st.form_submit_button("Continue to Legal Disclaimer", type="primary", use_container_width=True)

        if submitted:
            if not email or not company_name:
                st.error("Please fill in all required fields (Email and Company Name)")
            else:
                # Save to session state
                st.session_state.registration = {
                    'email': email,
                    'company_name': company_name,
                    'contact_name': contact_name,
                    'company_website': company_website,
                    'ip_addresses': [ip.strip() for ip in ip_addresses.split('\n') if ip.strip()][:config.MAX_IPS_PER_SCAN],
                    'urls': [url.strip() for url in urls.split('\n') if url.strip()][:config.MAX_URLS_PER_SCAN],
                    'emails_to_test': [e.strip() for e in emails_to_test.split('\n') if e.strip()][:config.MAX_EMAILS_PER_PHISHING_TEST],
                    'git_repos': [r.strip() for r in git_repos.split('\n') if r.strip()][:config.MAX_REPOS_PER_SCAN],
                    'domain': domain_for_dark_web.strip() or company_website.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
                }

                # Create or get user
                user = db.get_user_by_email(email)
                if not user:
                    user = db.create_user(email, company_name)

                st.session_state.user = user
                st.session_state.current_step = 'disclaimers'
                st.rerun()

    if st.button("← Back"):
        st.session_state.current_step = 'welcome'
        st.rerun()


def show_disclaimers_page():
    """Display legal disclaimers"""
    st.markdown("## Step 2: Legal Disclaimers")

    st.markdown("""
    <div class="disclaimer-box">
        <strong>Important:</strong> Please read and accept all disclaimers before proceeding with the assessment.
    </div>
    """, unsafe_allow_html=True)

    # Assessment Disclaimer
    st.markdown("### Security Assessment Disclaimer")
    disclaimer_text = LEGAL_DISCLAIMERS['assessment_disclaimer'].format(
        retention_days=config.REPORT_RETENTION_DAYS
    )
    st.markdown(disclaimer_text)

    assessment_accepted = st.checkbox("I have read and accept the Security Assessment Disclaimer")

    # Phishing Disclaimer
    st.markdown("### Phishing Simulation Consent")
    st.markdown(LEGAL_DISCLAIMERS['phishing_disclaimer'])

    phishing_accepted = st.checkbox("I have read and accept the Phishing Simulation Consent")

    # Subscription Terms
    st.markdown("### Training Subscription Terms")
    st.markdown(LEGAL_DISCLAIMERS['subscription_terms'])

    subscription_accepted = st.checkbox("I have read and accept the Training Subscription Terms")

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("← Back"):
            st.session_state.current_step = 'registration'
            st.rerun()

    with col2:
        if st.button("Accept & Continue to Payment", type="primary", disabled=not (assessment_accepted and phishing_accepted and subscription_accepted)):
            st.session_state.disclaimers_accepted = True

            # Update user disclaimers acceptance
            if st.session_state.user:
                db.update_user_disclaimers(st.session_state.user['id'], True)

            st.session_state.current_step = 'payment'
            st.rerun()


def show_payment_page():
    """Display payment page"""
    st.markdown("## Step 3: Payment")

    prices = stripe_service.get_price_display()

    st.markdown(f"""
    ### Order Summary

    | Item | Price |
    |------|-------|
    | Comprehensive Security Assessment | {prices['assessment']} |

    **Optional Add-on:**
    - Monthly Training Subscription: {prices['training_monthly']}
    """)

    include_training = st.checkbox("Add Monthly Training Subscription")

    st.markdown("---")

    # Demo mode notice
    if not stripe_service.is_configured():
        st.info("""
        **Demo Mode**: Stripe is not configured. Click 'Complete Demo Payment' to proceed with a simulated payment.

        To enable real payments, configure your Stripe API keys in the environment variables.
        """)

        col1, col2 = st.columns(2)

        with col1:
            if st.button("← Back"):
                st.session_state.current_step = 'disclaimers'
                st.rerun()

        with col2:
            if st.button("Complete Demo Payment", type="primary"):
                # Create assessment
                assessment_id = db.create_assessment(st.session_state.user['id'])
                db.update_assessment_payment(assessment_id, 'paid', 'demo_payment')

                st.session_state.assessment_id = assessment_id
                st.session_state.payment_complete = True
                st.session_state.include_training = include_training
                st.session_state.current_step = 'assessment'
                st.rerun()
    else:
        # Real Stripe payment
        col1, col2 = st.columns(2)

        with col1:
            if st.button("← Back"):
                st.session_state.current_step = 'disclaimers'
                st.rerun()

        with col2:
            if st.button("Proceed to Checkout", type="primary"):
                # Create assessment
                assessment_id = db.create_assessment(st.session_state.user['id'])
                st.session_state.assessment_id = assessment_id

                # Create Stripe checkout session
                session = stripe_service.create_assessment_checkout_session(
                    customer_id=st.session_state.user.get('stripe_customer_id', ''),
                    assessment_id=assessment_id,
                    success_url=f"{config.COMPANY_WEBSITE}/success?session_id={{CHECKOUT_SESSION_ID}}",
                    cancel_url=f"{config.COMPANY_WEBSITE}/cancel"
                )

                if session:
                    st.markdown(f"[Click here to complete payment]({session['url']})")
                else:
                    st.error("Failed to create checkout session. Please try again.")


def show_assessment_page():
    """Display the main assessment page"""
    st.markdown("## Step 4: Security Assessment")

    # Progress indicator
    steps = ['SOC2 Assessment', 'Vulnerability Scan', 'Phishing Test', 'Git Scan', 'Dark Web Scan', 'Report']

    if 'assessment_step' not in st.session_state:
        st.session_state.assessment_step = 0

    # Progress bar
    progress = (st.session_state.assessment_step / len(steps))
    st.progress(progress)
    st.caption(f"Step {st.session_state.assessment_step + 1} of {len(steps)}: {steps[st.session_state.assessment_step]}")

    # Current step content
    if st.session_state.assessment_step == 0:
        show_soc2_assessment()
    elif st.session_state.assessment_step == 1:
        show_vulnerability_scan()
    elif st.session_state.assessment_step == 2:
        show_phishing_test()
    elif st.session_state.assessment_step == 3:
        show_git_scan()
    elif st.session_state.assessment_step == 4:
        show_dark_web_scan()
    elif st.session_state.assessment_step == 5:
        show_report()


def show_soc2_assessment():
    """Display SOC2 assessment questionnaire"""
    st.markdown("### SOC2 Type 1 Self-Assessment")
    st.info("Answer the following questions about your organization's security practices. Be honest for the most accurate assessment.")

    questions = soc2_service.get_questions()
    questions_by_category = soc2_service.get_questions_by_category()

    if 'soc2_responses' not in st.session_state:
        st.session_state.soc2_responses = {}

    # Display questions by category
    for category, cat_questions in questions_by_category.items():
        category_name = cat_questions[0]['category_name'] if cat_questions else category

        with st.expander(f"**{category_name}** ({len(cat_questions)} questions)", expanded=True):
            for q in cat_questions:
                st.markdown(f"**{q['question']}**")
                st.caption(q['description'])

                options = [opt['label'] for opt in q['options']]
                response = st.radio(
                    "Select your answer:",
                    options,
                    key=f"soc2_{q['id']}",
                    horizontal=False,
                    label_visibility="collapsed"
                )

                # Save response
                if response:
                    for opt in q['options']:
                        if opt['label'] == response:
                            st.session_state.soc2_responses[q['id']] = opt['value']
                            break

                st.markdown("---")

    # Navigation
    col1, col2 = st.columns(2)

    with col2:
        total_questions = len(questions)
        answered = len(st.session_state.soc2_responses)

        if st.button(f"Continue ({answered}/{total_questions} answered)", type="primary", disabled=answered < total_questions // 2):
            # Calculate results
            results = soc2_service.calculate_score(st.session_state.soc2_responses)
            recommendations = soc2_service.generate_recommendations(st.session_state.soc2_responses)

            st.session_state.assessment_results['soc2'] = {
                **results,
                'recommendations': recommendations
            }

            # Save to database
            for q_id, response in st.session_state.soc2_responses.items():
                question_data = next((q for q in questions if q['id'] == q_id), None)
                if question_data:
                    db.save_soc2_response(
                        st.session_state.assessment_id,
                        question_data['category'],
                        q_id,
                        question_data['question'],
                        response
                    )

            st.session_state.assessment_step = 1
            st.rerun()


def show_vulnerability_scan():
    """Display vulnerability scanning step"""
    st.markdown("### Vulnerability Scan")

    registration = st.session_state.get('registration', {})
    ips = registration.get('ip_addresses', [])
    urls = registration.get('urls', [])

    if not ips and not urls:
        st.warning("No IP addresses or URLs were provided for scanning. Click 'Skip' to continue.")

        if st.button("Skip this step"):
            st.session_state.assessment_results['vulnerability'] = []
            st.session_state.assessment_step = 2
            st.rerun()
        return

    st.info(f"Scanning {len(ips)} IP address(es) and {len(urls)} URL(s)...")

    if 'vuln_scan_complete' not in st.session_state:
        st.session_state.vuln_scan_complete = False
        st.session_state.vuln_results = []

    if not st.session_state.vuln_scan_complete:
        with st.spinner("Running vulnerability scans..."):
            results = []

            # Scan IPs
            for ip in ips:
                st.text(f"Scanning IP: {ip}")
                result = vuln_scanner.scan_ip(ip)
                results.append(result)

            # Scan URLs
            for url in urls:
                st.text(f"Scanning URL: {url}")
                result = vuln_scanner.scan_url(url)
                results.append(result)

            st.session_state.vuln_results = results
            st.session_state.vuln_scan_complete = True

            # Save to database
            for result in results:
                db.save_vulnerability_scan(
                    st.session_state.assessment_id,
                    result['target_type'],
                    result['target'],
                    result.get('findings'),
                    result.get('risk_score')
                )

    # Display results
    st.markdown("### Scan Results")

    for result in st.session_state.vuln_results:
        with st.expander(f"**{result['target']}** - Score: {result.get('risk_score', 'N/A')}", expanded=True):
            if result.get('status') == 'error':
                st.error(result.get('error', 'Scan failed'))
            else:
                summary = result.get('summary', {})
                col1, col2, col3 = st.columns(3)
                col1.metric("Critical", summary.get('critical_findings', 0))
                col2.metric("High", summary.get('high_findings', 0))
                col3.metric("Medium", summary.get('medium_findings', 0))

                for finding in result.get('findings', [])[:10]:
                    severity_colors = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢',
                        'INFO': '🔵'
                    }
                    icon = severity_colors.get(finding['severity'], '⚪')
                    st.markdown(f"{icon} **{finding['title']}**")
                    st.caption(finding['description'])

    st.session_state.assessment_results['vulnerability'] = st.session_state.vuln_results

    if st.button("Continue to Phishing Test", type="primary"):
        st.session_state.assessment_step = 2
        st.rerun()


def show_phishing_test():
    """Display phishing test step"""
    st.markdown("### Phishing Awareness Test")

    registration = st.session_state.get('registration', {})
    emails = registration.get('emails_to_test', [])

    if not emails:
        st.warning("No email addresses were provided for phishing testing. Click 'Skip' to continue.")

        if st.button("Skip this step"):
            st.session_state.assessment_results['phishing'] = {
                'total_emails': 0,
                'risk_score': 100,
                'risk_level': 'N/A',
                'message': 'No emails tested'
            }
            st.session_state.assessment_step = 3
            st.rerun()
        return

    st.info(f"Testing phishing awareness for {len(emails)} email address(es)")

    # Select template
    templates = phishing_service.get_templates()

    template_options = {t['name']: t['id'] for t in templates}
    selected_template_name = st.selectbox(
        "Select phishing template",
        options=list(template_options.keys())
    )
    selected_template = template_options[selected_template_name]

    # Show template info
    template_info = next((t for t in templates if t['id'] == selected_template), None)
    if template_info:
        st.caption(f"Difficulty: {template_info['difficulty']} | Category: {template_info['category']}")
        st.caption(template_info['description'])

    st.markdown("---")

    if 'phishing_complete' not in st.session_state:
        st.session_state.phishing_complete = False

    if not st.session_state.phishing_complete:
        if st.button("Run Phishing Simulation", type="primary"):
            with st.spinner("Running phishing simulation..."):
                # In demo mode, simulate results
                if not phishing_service.smtp_configured:
                    results = phishing_service.simulate_results(
                        len(emails),
                        template_info['difficulty'] if template_info else 'medium'
                    )
                else:
                    # Create actual campaign
                    campaign = phishing_service.create_campaign(
                        st.session_state.assessment_id,
                        emails,
                        selected_template
                    )
                    # For real campaigns, results would come from tracking
                    results = phishing_service.simulate_results(len(emails), template_info['difficulty'])

                st.session_state.phishing_results = results
                st.session_state.phishing_complete = True

                # Save to database
                for email in emails:
                    db.save_phishing_test(
                        st.session_state.assessment_id,
                        email,
                        selected_template
                    )

                st.rerun()
    else:
        results = st.session_state.phishing_results

        # Display results
        st.markdown("### Phishing Test Results")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Emails Tested", results['total_emails'])
        col2.metric("Click Rate", f"{results['click_rate']}%")
        col3.metric("Report Rate", f"{results['report_rate']}%")
        col4.metric("Risk Level", results['risk_level'])

        # Interpretation
        risk_colors = {
            'LOW': 'green',
            'MEDIUM': 'orange',
            'HIGH': 'red',
            'CRITICAL': 'red'
        }
        color = risk_colors.get(results['risk_level'], 'gray')
        st.markdown(f"**Resilience Score:** :{'green' if results['risk_score'] >= 70 else 'red'}[{results['risk_score']}%]")

        # Recommendations
        st.markdown("### Recommendations")
        for rec in results.get('recommendations', []):
            st.markdown(f"- {rec}")

        st.session_state.assessment_results['phishing'] = results

        if st.button("Continue to Git Scan", type="primary"):
            st.session_state.assessment_step = 3
            st.rerun()


def show_git_scan():
    """Display Git repository scan step"""
    st.markdown("### Git Repository Security Scan")

    registration = st.session_state.get('registration', {})
    repos = registration.get('git_repos', [])

    if not repos:
        st.warning("No Git repositories were provided for scanning. Click 'Skip' to continue.")

        if st.button("Skip this step"):
            st.session_state.assessment_results['git'] = []
            st.session_state.assessment_step = 4
            st.rerun()
        return

    st.info(f"Scanning {len(repos)} repository(ies) for security issues...")

    if 'git_scan_complete' not in st.session_state:
        st.session_state.git_scan_complete = False
        st.session_state.git_results = []

    if not st.session_state.git_scan_complete:
        with st.spinner("Scanning repositories..."):
            results = []

            for repo in repos:
                st.text(f"Scanning: {repo}")
                try:
                    result = git_scanner.scan_repository(repo)
                except Exception as e:
                    result = git_scanner.simulate_scan(repo)

                results.append(result)

                # Save to database
                db.save_git_scan(
                    st.session_state.assessment_id,
                    repo,
                    result.get('findings'),
                    result.get('secrets_found', 0),
                    result.get('vulnerabilities_found', 0),
                    result.get('risk_score')
                )

            st.session_state.git_results = results
            st.session_state.git_scan_complete = True
            st.rerun()

    # Display results
    st.markdown("### Scan Results")

    for result in st.session_state.git_results:
        with st.expander(f"**{result.get('repo_url', 'Repository')}** - Score: {result.get('risk_score', 'N/A')}", expanded=True):
            if result.get('status') == 'error':
                st.error(result.get('error', 'Scan failed'))
            else:
                col1, col2, col3 = st.columns(3)
                col1.metric("Secrets Found", result.get('secrets_found', 0))
                col2.metric("Vulnerabilities", result.get('vulnerabilities_found', 0))
                col3.metric("Files Scanned", result.get('files_scanned', 0))

                for finding in result.get('findings', [])[:10]:
                    severity_colors = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢',
                        'INFO': '🔵'
                    }
                    icon = severity_colors.get(finding.get('severity', 'INFO'), '⚪')
                    st.markdown(f"{icon} **{finding.get('title', 'Finding')}**")
                    st.caption(finding.get('description', ''))
                    if finding.get('file'):
                        st.caption(f"File: `{finding['file']}`")

    st.session_state.assessment_results['git'] = st.session_state.git_results

    if st.button("Continue to Dark Web Scan", type="primary"):
        st.session_state.assessment_step = 4
        st.rerun()


def show_dark_web_scan():
    """Display Dark Web monitoring step"""
    st.markdown("### Dark Web Exposure Scan")

    registration = st.session_state.get('registration', {})
    domain = registration.get('domain', '')

    if not domain:
        st.warning("No domain was provided for dark web monitoring. Click 'Skip' to continue.")

        if st.button("Skip this step"):
            st.session_state.assessment_results['dark_web'] = {
                'domain': '',
                'breaches_found': 0,
                'risk_score': 100,
                'findings': []
            }
            st.session_state.assessment_step = 5
            st.rerun()
        return

    st.info(f"Checking dark web exposure for: **{domain}**")

    if 'dark_web_complete' not in st.session_state:
        st.session_state.dark_web_complete = False

    if not st.session_state.dark_web_complete:
        with st.spinner("Scanning dark web databases..."):
            result = dark_web_scanner.scan_domain(domain)

            st.session_state.dark_web_result = result
            st.session_state.dark_web_complete = True

            # Save to database
            db.save_dark_web_scan(
                st.session_state.assessment_id,
                domain,
                result.get('findings'),
                result.get('breaches_found', 0),
                result.get('exposed_credentials', 0),
                result.get('risk_score')
            )

            st.rerun()

    # Display results
    result = st.session_state.dark_web_result

    st.markdown("### Scan Results")

    col1, col2, col3 = st.columns(3)
    col1.metric("Breaches Found", result.get('breaches_found', 0))
    col2.metric("Exposed Credentials", result.get('exposed_credentials', 0))
    col3.metric("Risk Score", result.get('risk_score', 100))

    # Findings
    if result.get('findings'):
        st.markdown("### Detailed Findings")
        for finding in result['findings']:
            severity_colors = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'INFO': '🔵'
            }
            icon = severity_colors.get(finding.get('severity', 'INFO'), '⚪')
            st.markdown(f"{icon} **{finding.get('title', 'Finding')}**")
            st.caption(finding.get('description', ''))

    # Summary
    summary = dark_web_scanner.get_breach_summary(result.get('findings', []))
    st.markdown(f"**Status:** {summary['message']}")

    if summary.get('recommendations'):
        st.markdown("### Recommendations")
        for rec in summary['recommendations']:
            st.markdown(f"- {rec}")

    st.session_state.assessment_results['dark_web'] = result

    if st.button("Generate Final Report", type="primary"):
        st.session_state.assessment_step = 5
        st.rerun()


def show_report():
    """Display and generate final report"""
    st.markdown("### Assessment Complete!")

    with st.spinner("Generating your comprehensive security report..."):
        # Generate report
        report = report_generator.generate_report(
            assessment_id=st.session_state.assessment_id,
            company_info=st.session_state.get('registration', {}),
            soc2_results=st.session_state.assessment_results.get('soc2', {}),
            vulnerability_results=st.session_state.assessment_results.get('vulnerability', []),
            phishing_results=st.session_state.assessment_results.get('phishing', {}),
            git_results=st.session_state.assessment_results.get('git', []),
            dark_web_results=st.session_state.assessment_results.get('dark_web', {})
        )

        # Save report to database
        db.save_report(st.session_state.assessment_id, report)

        # Update assessment status
        db.update_assessment_score(
            st.session_state.assessment_id,
            report['overall_score'],
            report['overall_risk_level']
        )

    # Display Executive Summary
    st.markdown("## Executive Summary")

    col1, col2 = st.columns([1, 2])

    with col1:
        score = report['overall_score']
        risk_level = report['overall_risk_level']

        score_color = {
            'CRITICAL': 'score-critical',
            'HIGH': 'score-high',
            'MEDIUM': 'score-medium',
            'LOW': 'score-low',
            'MINIMAL': 'score-minimal'
        }.get(risk_level, '')

        st.markdown(f"""
        <div class="score-card">
            <div class="score-value {score_color}">{score}</div>
            <div>Overall Security Score</div>
            <div><strong>{risk_level}</strong> Risk</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        exec_summary = report.get('executive_summary', {})
        st.markdown(f"**{exec_summary.get('status_description', '')}**")

        metrics = exec_summary.get('key_metrics', {})
        st.markdown(f"""
        - **Critical Findings:** {metrics.get('critical_findings', 0)}
        - **High Findings:** {metrics.get('high_findings', 0)}
        - **SOC2 Readiness:** {metrics.get('soc2_readiness', 'N/A')}
        - **Phishing Resilience:** {metrics.get('phishing_resilience', 'N/A')}
        """)

    # Priority Recommendations
    st.markdown("## Priority Recommendations")

    for rec in report.get('priority_recommendations', [])[:5]:
        priority_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        icon = priority_colors.get(rec['priority'], '⚪')

        st.markdown(f"{icon} **[{rec['priority']}] {rec['category']}**")
        st.markdown(f"*Issue:* {rec['issue']}")
        st.markdown(f"*Recommendation:* {rec['recommendation']}")
        st.markdown("---")

    # Next Steps
    st.markdown("## Next Steps")

    for step in report.get('next_steps', []):
        st.markdown(f"**Step {step['step']}: {step['action']}**")
        st.caption(step['description'])
        st.caption(f"Timeline: {step['timeline']}")

    # Download Report
    st.markdown("---")
    st.markdown("## Download Your Report")

    # Generate HTML report
    html_report = report_generator.export_to_html(report)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label="📄 Download HTML Report",
            data=html_report,
            file_name=f"vcso_security_report_{datetime.now().strftime('%Y%m%d')}.html",
            mime="text/html"
        )

    with col2:
        st.download_button(
            label="📋 Download JSON Data",
            data=json.dumps(report, indent=2),
            file_name=f"vcso_security_report_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json"
        )

    # CTA for low scores
    if report['overall_score'] < 70:
        st.markdown("---")
        st.markdown("""
        <div style="background: #16213e; color: white; padding: 2rem; border-radius: 10px; text-align: center;">
            <h2>Need Help Improving Your Security Posture?</h2>
            <p>Your assessment reveals areas that need attention. VCSO.AI can help you remediate findings and achieve compliance.</p>
            <p><a href="https://www.vcso.ai/contact" style="color: #4da6ff;">Schedule a Free Consultation →</a></p>
        </div>
        """, unsafe_allow_html=True)

    # Training upsell
    st.markdown("---")
    st.markdown("## Continuous Security Improvement")

    if st.session_state.get('include_training'):
        st.success("Thank you for subscribing to our training program!")
        if st.button("Go to Training Portal"):
            st.session_state.current_step = 'training'
            st.rerun()
    else:
        st.markdown("""
        Your assessment is complete, but security is an ongoing journey.

        **Subscribe to our Monthly Training Program:**
        - Security awareness training for your team
        - Regular phishing simulations
        - Progress tracking and certificates
        - New content updated monthly
        """)

        if st.button("Subscribe to Training"):
            st.session_state.current_step = 'training_signup'
            st.rerun()


def show_training_page():
    """Display training module"""
    st.markdown("## Security Awareness Training")

    # Get user progress
    user_progress = []
    if st.session_state.user:
        user_progress = db.get_training_progress(st.session_state.user['id'])

    completed_modules = [p['module_id'] for p in user_progress if p['completed']]

    # Progress overview
    progress = training_manager.calculate_progress(completed_modules)

    col1, col2, col3 = st.columns(3)
    col1.metric("Modules Completed", f"{progress['completed_modules']}/{progress['total_modules']}")
    col2.metric("Progress", f"{progress['progress_percentage']}%")
    col3.metric("Time Remaining", f"{progress['remaining_minutes']} min")

    st.progress(progress['progress_percentage'] / 100)

    st.markdown("---")

    # Module list
    modules = training_manager.get_all_modules()

    for module in modules:
        is_completed = module['id'] in completed_modules

        with st.expander(f"{'✅' if is_completed else '📚'} {module['title']} ({module['duration_minutes']} min)"):
            st.markdown(module['description'])
            st.caption(f"Category: {module['category']} | Difficulty: {module['difficulty']}")

            if is_completed:
                st.success("Completed!")
            else:
                if st.button(f"Start Module", key=f"start_{module['id']}"):
                    st.session_state.current_training_module = module['id']
                    st.session_state.current_step = 'training_module'
                    st.rerun()


def show_training_module():
    """Display a specific training module"""
    module_id = st.session_state.get('current_training_module')
    if not module_id:
        st.session_state.current_step = 'training'
        st.rerun()
        return

    module = training_manager.get_module(module_id)
    if not module:
        st.error("Module not found")
        return

    st.markdown(f"## {module['title']}")
    st.caption(f"Duration: {module['duration_minutes']} minutes | Difficulty: {module['difficulty']}")

    # Content
    for section in module['content']:
        if section['type'] == 'text':
            st.markdown(f"### {section['title']}")
            st.markdown(section['content'])
        elif section['type'] == 'example':
            st.markdown(f"### {section['title']}")
            st.info(section['content'])

        st.markdown("---")

    # Quiz
    st.markdown("## Knowledge Check")

    quiz_answers = []
    for i, question in enumerate(module['quiz']):
        st.markdown(f"**{i+1}. {question['question']}**")
        answer = st.radio(
            "Select your answer:",
            question['options'],
            key=f"quiz_{module_id}_{i}",
            label_visibility="collapsed"
        )
        quiz_answers.append(question['options'].index(answer) if answer else -1)

    if st.button("Submit Quiz", type="primary"):
        results = training_manager.evaluate_quiz(module_id, quiz_answers)

        if results.get('passed'):
            st.success(f"🎉 {results['message']} Score: {results['score']}%")

            # Save progress
            if st.session_state.user:
                db.save_training_progress(
                    st.session_state.user['id'],
                    module_id,
                    completed=True,
                    score=results['score']
                )
        else:
            st.error(f"❌ {results['message']} Score: {results['score']}%")

        # Show detailed results
        for result in results['results']:
            if result['is_correct']:
                st.success(f"✓ {result['question']}")
            else:
                st.error(f"✗ {result['question']}")
                st.caption(f"Your answer: {result['your_answer']}")
                st.caption(f"Correct answer: {result['correct_answer']}")
            st.caption(result['explanation'])

    if st.button("← Back to Training"):
        st.session_state.current_step = 'training'
        st.rerun()


# Main routing
def main():
    """Main application router"""

    # Sidebar navigation
    with st.sidebar:
        st.image("https://via.placeholder.com/200x60?text=VCSO.AI", use_container_width=True)
        st.markdown("---")

        if st.session_state.user:
            st.markdown(f"**Welcome!**")
            st.caption(st.session_state.user.get('email', ''))
            st.markdown("---")

        # Navigation
        if st.button("🏠 Home", use_container_width=True):
            st.session_state.current_step = 'welcome'
            st.rerun()

        if st.session_state.payment_complete:
            if st.button("📋 Assessment", use_container_width=True):
                st.session_state.current_step = 'assessment'
                st.rerun()

            if st.button("📚 Training", use_container_width=True):
                st.session_state.current_step = 'training'
                st.rerun()

        st.markdown("---")
        st.markdown(f"[{config.COMPANY_WEBSITE}]({config.COMPANY_WEBSITE})")
        st.caption("© 2024 VCSO.AI")

    # Page routing
    step = st.session_state.current_step

    if step == 'welcome':
        show_welcome_page()
    elif step == 'registration':
        show_registration_page()
    elif step == 'disclaimers':
        show_disclaimers_page()
    elif step == 'payment':
        show_payment_page()
    elif step == 'assessment':
        show_assessment_page()
    elif step == 'training':
        show_training_page()
    elif step == 'training_module':
        show_training_module()
    else:
        show_welcome_page()


if __name__ == "__main__":
    main()
