"""
Database module for VCSO Security Assessment Platform
Uses SQLite for simplicity and portability
"""

import sqlite3
import json
import uuid
from datetime import datetime
from typing import Optional, Dict, List, Any
from contextlib import contextmanager
import os

from config import config


def get_db_path() -> str:
    """Get database path, creating directory if needed"""
    db_dir = os.path.dirname(config.DATABASE_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    return config.DATABASE_PATH


@contextmanager
def get_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_database():
    """Initialize database tables"""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                company_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                stripe_customer_id TEXT,
                disclaimers_accepted BOOLEAN DEFAULT FALSE,
                disclaimers_accepted_at TIMESTAMP
            )
        """)

        # Assessments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                payment_status TEXT DEFAULT 'unpaid',
                stripe_payment_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                overall_score REAL,
                risk_level TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # SOC2 Assessment Responses
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS soc2_responses (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                category TEXT NOT NULL,
                question_id TEXT NOT NULL,
                question TEXT NOT NULL,
                response TEXT,
                score REAL,
                ai_analysis TEXT,
                recommendations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            )
        """)

        # Vulnerability Scan Results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_scans (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                findings TEXT,
                risk_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            )
        """)

        # Phishing Test Results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_tests (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                email TEXT NOT NULL,
                template_used TEXT,
                sent_at TIMESTAMP,
                opened_at TIMESTAMP,
                clicked_at TIMESTAMP,
                reported_at TIMESTAMP,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            )
        """)

        # Git Repository Scan Results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS git_scans (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                repo_url TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                secrets_found INTEGER DEFAULT 0,
                vulnerabilities_found INTEGER DEFAULT 0,
                findings TEXT,
                risk_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            )
        """)

        # Dark Web Scan Results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dark_web_scans (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                breaches_found INTEGER DEFAULT 0,
                exposed_credentials INTEGER DEFAULT 0,
                findings TEXT,
                risk_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            )
        """)

        # Reports
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                report_data TEXT,
                pdf_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            )
        """)

        # Training Subscriptions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                stripe_subscription_id TEXT,
                status TEXT DEFAULT 'inactive',
                plan_type TEXT DEFAULT 'monthly',
                started_at TIMESTAMP,
                cancelled_at TIMESTAMP,
                current_period_end TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # Training Progress
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS training_progress (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                module_id TEXT NOT NULL,
                completed BOOLEAN DEFAULT FALSE,
                score REAL,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        conn.commit()


# User Operations
def create_user(email: str, company_name: str = None) -> Dict[str, Any]:
    """Create a new user"""
    user_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (id, email, company_name) VALUES (?, ?, ?)",
            (user_id, email, company_name)
        )
    return {"id": user_id, "email": email, "company_name": company_name}


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by ID"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def update_user_disclaimers(user_id: str, accepted: bool = True):
    """Update user disclaimer acceptance"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE users SET disclaimers_accepted = ?, disclaimers_accepted_at = ?
               WHERE id = ?""",
            (accepted, datetime.now().isoformat() if accepted else None, user_id)
        )


def update_user_stripe_customer(user_id: str, stripe_customer_id: str):
    """Update user's Stripe customer ID"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET stripe_customer_id = ? WHERE id = ?",
            (stripe_customer_id, user_id)
        )


# Assessment Operations
def create_assessment(user_id: str) -> str:
    """Create a new assessment"""
    assessment_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO assessments (id, user_id) VALUES (?, ?)",
            (assessment_id, user_id)
        )
    return assessment_id


def get_assessment(assessment_id: str) -> Optional[Dict[str, Any]]:
    """Get assessment by ID"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_assessments(user_id: str) -> List[Dict[str, Any]]:
    """Get all assessments for a user"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM assessments WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


def update_assessment_status(assessment_id: str, status: str):
    """Update assessment status"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE assessments SET status = ? WHERE id = ?",
            (status, assessment_id)
        )


def update_assessment_payment(assessment_id: str, payment_status: str, stripe_payment_id: str = None):
    """Update assessment payment status"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE assessments SET payment_status = ?, stripe_payment_id = ? WHERE id = ?",
            (payment_status, stripe_payment_id, assessment_id)
        )


def update_assessment_score(assessment_id: str, score: float, risk_level: str):
    """Update assessment overall score"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE assessments SET overall_score = ?, risk_level = ?,
               completed_at = ?, status = 'completed' WHERE id = ?""",
            (score, risk_level, datetime.now().isoformat(), assessment_id)
        )


# SOC2 Response Operations
def save_soc2_response(assessment_id: str, category: str, question_id: str,
                       question: str, response: str, score: float = None,
                       ai_analysis: str = None, recommendations: str = None) -> str:
    """Save a SOC2 assessment response"""
    response_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO soc2_responses
               (id, assessment_id, category, question_id, question, response, score, ai_analysis, recommendations)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (response_id, assessment_id, category, question_id, question, response, score, ai_analysis, recommendations)
        )
    return response_id


def get_soc2_responses(assessment_id: str) -> List[Dict[str, Any]]:
    """Get all SOC2 responses for an assessment"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM soc2_responses WHERE assessment_id = ? ORDER BY category, question_id",
            (assessment_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


# Vulnerability Scan Operations
def save_vulnerability_scan(assessment_id: str, target_type: str, target: str,
                            findings: Dict = None, risk_score: float = None) -> str:
    """Save vulnerability scan results"""
    scan_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        status = 'completed' if findings else 'pending'
        cursor.execute(
            """INSERT INTO vulnerability_scans
               (id, assessment_id, target_type, target, status, findings, risk_score, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, assessment_id, target_type, target, status,
             json.dumps(findings) if findings else None, risk_score,
             datetime.now().isoformat() if findings else None)
        )
    return scan_id


def get_vulnerability_scans(assessment_id: str) -> List[Dict[str, Any]]:
    """Get vulnerability scans for an assessment"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM vulnerability_scans WHERE assessment_id = ?",
            (assessment_id,)
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            d = dict(row)
            if d.get('findings'):
                d['findings'] = json.loads(d['findings'])
            results.append(d)
        return results


# Phishing Test Operations
def save_phishing_test(assessment_id: str, email: str, template_used: str) -> str:
    """Save phishing test record"""
    test_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO phishing_tests (id, assessment_id, email, template_used, sent_at, status)
               VALUES (?, ?, ?, ?, ?, 'sent')""",
            (test_id, assessment_id, email, template_used, datetime.now().isoformat())
        )
    return test_id


def update_phishing_test(test_id: str, opened: bool = False, clicked: bool = False, reported: bool = False):
    """Update phishing test interaction"""
    with get_connection() as conn:
        cursor = conn.cursor()
        updates = []
        params = []
        if opened:
            updates.append("opened_at = ?")
            params.append(datetime.now().isoformat())
        if clicked:
            updates.append("clicked_at = ?")
            params.append(datetime.now().isoformat())
        if reported:
            updates.append("reported_at = ?")
            params.append(datetime.now().isoformat())

        if updates:
            params.append(test_id)
            cursor.execute(
                f"UPDATE phishing_tests SET {', '.join(updates)} WHERE id = ?",
                params
            )


def get_phishing_tests(assessment_id: str) -> List[Dict[str, Any]]:
    """Get phishing tests for an assessment"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM phishing_tests WHERE assessment_id = ?",
            (assessment_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


# Git Scan Operations
def save_git_scan(assessment_id: str, repo_url: str, findings: Dict = None,
                  secrets_found: int = 0, vulnerabilities_found: int = 0,
                  risk_score: float = None) -> str:
    """Save git scan results"""
    scan_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        status = 'completed' if findings else 'pending'
        cursor.execute(
            """INSERT INTO git_scans
               (id, assessment_id, repo_url, status, secrets_found, vulnerabilities_found, findings, risk_score, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, assessment_id, repo_url, status, secrets_found, vulnerabilities_found,
             json.dumps(findings) if findings else None, risk_score,
             datetime.now().isoformat() if findings else None)
        )
    return scan_id


def get_git_scans(assessment_id: str) -> List[Dict[str, Any]]:
    """Get git scans for an assessment"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM git_scans WHERE assessment_id = ?",
            (assessment_id,)
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            d = dict(row)
            if d.get('findings'):
                d['findings'] = json.loads(d['findings'])
            results.append(d)
        return results


# Dark Web Scan Operations
def save_dark_web_scan(assessment_id: str, domain: str, findings: Dict = None,
                       breaches_found: int = 0, exposed_credentials: int = 0,
                       risk_score: float = None) -> str:
    """Save dark web scan results"""
    scan_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        status = 'completed' if findings else 'pending'
        cursor.execute(
            """INSERT INTO dark_web_scans
               (id, assessment_id, domain, status, breaches_found, exposed_credentials, findings, risk_score, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, assessment_id, domain, status, breaches_found, exposed_credentials,
             json.dumps(findings) if findings else None, risk_score,
             datetime.now().isoformat() if findings else None)
        )
    return scan_id


def get_dark_web_scans(assessment_id: str) -> List[Dict[str, Any]]:
    """Get dark web scans for an assessment"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM dark_web_scans WHERE assessment_id = ?",
            (assessment_id,)
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            d = dict(row)
            if d.get('findings'):
                d['findings'] = json.loads(d['findings'])
            results.append(d)
        return results


# Report Operations
def save_report(assessment_id: str, report_data: Dict, pdf_path: str = None) -> str:
    """Save generated report"""
    report_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO reports (id, assessment_id, report_data, pdf_path) VALUES (?, ?, ?, ?)",
            (report_id, assessment_id, json.dumps(report_data), pdf_path)
        )
    return report_id


def get_report(assessment_id: str) -> Optional[Dict[str, Any]]:
    """Get report for an assessment"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM reports WHERE assessment_id = ? ORDER BY created_at DESC LIMIT 1",
            (assessment_id,)
        )
        row = cursor.fetchone()
        if row:
            d = dict(row)
            if d.get('report_data'):
                d['report_data'] = json.loads(d['report_data'])
            return d
        return None


# Subscription Operations
def create_subscription(user_id: str, stripe_subscription_id: str = None) -> str:
    """Create a subscription"""
    sub_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO subscriptions (id, user_id, stripe_subscription_id, status, started_at)
               VALUES (?, ?, ?, 'active', ?)""",
            (sub_id, user_id, stripe_subscription_id, datetime.now().isoformat())
        )
    return sub_id


def get_user_subscription(user_id: str) -> Optional[Dict[str, Any]]:
    """Get active subscription for user"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY started_at DESC LIMIT 1",
            (user_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def update_subscription_status(subscription_id: str, status: str):
    """Update subscription status"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE subscriptions SET status = ?, cancelled_at = ? WHERE id = ?",
            (status, datetime.now().isoformat() if status == 'cancelled' else None, subscription_id)
        )


# Training Progress Operations
def save_training_progress(user_id: str, module_id: str, completed: bool = False, score: float = None):
    """Save training module progress"""
    progress_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        # Check if progress exists
        cursor.execute(
            "SELECT id FROM training_progress WHERE user_id = ? AND module_id = ?",
            (user_id, module_id)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """UPDATE training_progress SET completed = ?, score = ?, completed_at = ?
                   WHERE user_id = ? AND module_id = ?""",
                (completed, score, datetime.now().isoformat() if completed else None, user_id, module_id)
            )
        else:
            cursor.execute(
                """INSERT INTO training_progress (id, user_id, module_id, completed, score, completed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (progress_id, user_id, module_id, completed, score,
                 datetime.now().isoformat() if completed else None)
            )


def get_training_progress(user_id: str) -> List[Dict[str, Any]]:
    """Get training progress for user"""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM training_progress WHERE user_id = ?",
            (user_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


# Initialize database on import
init_database()
