"""
Security Awareness Training Module
Provides training content and tracks progress
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class TrainingModule:
    """Training module definition"""
    id: str
    title: str
    description: str
    duration_minutes: int
    category: str
    difficulty: str
    content: List[Dict[str, Any]]
    quiz: List[Dict[str, Any]]


class TrainingManager:
    """Manage security awareness training"""

    def __init__(self):
        self.modules = self._load_modules()

    def _load_modules(self) -> List[TrainingModule]:
        """Load training modules"""
        modules_data = [
            {
                "id": "phishing_101",
                "title": "Phishing Awareness Fundamentals",
                "description": "Learn to identify and avoid phishing attacks",
                "duration_minutes": 15,
                "category": "Email Security",
                "difficulty": "Beginner",
                "content": [
                    {
                        "type": "text",
                        "title": "What is Phishing?",
                        "content": """
Phishing is a type of social engineering attack where attackers attempt to trick you into revealing sensitive information, such as passwords, credit card numbers, or personal data.

**Common Phishing Characteristics:**
- Urgent or threatening language
- Requests for personal information
- Suspicious sender addresses
- Generic greetings ("Dear Customer")
- Poor grammar and spelling
- Suspicious links or attachments
"""
                    },
                    {
                        "type": "text",
                        "title": "Types of Phishing Attacks",
                        "content": """
**1. Email Phishing**
Mass emails that appear to be from legitimate organizations.

**2. Spear Phishing**
Targeted attacks customized for specific individuals or organizations.

**3. Whaling**
Attacks targeting senior executives and high-profile individuals.

**4. Smishing**
Phishing via SMS text messages.

**5. Vishing**
Voice phishing through phone calls.
"""
                    },
                    {
                        "type": "example",
                        "title": "Spotting a Phishing Email",
                        "content": """
**Red Flags to Look For:**

1. **Check the sender's email address**
   - Legitimate: support@company.com
   - Suspicious: support@c0mpany-secure.com

2. **Hover over links before clicking**
   - Does the URL match the expected destination?
   - Look for misspellings or extra characters

3. **Verify requests through official channels**
   - Call the company directly using a known number
   - Don't use contact info from the suspicious email
"""
                    },
                    {
                        "type": "text",
                        "title": "What To Do If You Suspect Phishing",
                        "content": """
1. **Don't click any links or download attachments**
2. **Don't reply to the email**
3. **Report the email to your IT/Security team**
4. **Delete the email after reporting**
5. **If you clicked a link, change your password immediately**
6. **Monitor your accounts for suspicious activity**
"""
                    }
                ],
                "quiz": [
                    {
                        "question": "Which of the following is a common sign of a phishing email?",
                        "options": [
                            "Email from a known colleague",
                            "Urgent language demanding immediate action",
                            "Company letterhead",
                            "Proper grammar throughout"
                        ],
                        "correct": 1,
                        "explanation": "Phishing emails often use urgent or threatening language to pressure victims into acting quickly without thinking."
                    },
                    {
                        "question": "What should you do if you receive a suspicious email asking for your password?",
                        "options": [
                            "Reply with your password to verify it's legitimate",
                            "Click the link to see where it goes",
                            "Report it to IT and delete it",
                            "Forward it to colleagues for their opinion"
                        ],
                        "correct": 2,
                        "explanation": "Never provide passwords via email. Report suspicious emails to IT and delete them."
                    },
                    {
                        "question": "What is 'spear phishing'?",
                        "options": [
                            "Phishing using fishing-related themes",
                            "Mass email phishing campaigns",
                            "Targeted attacks customized for specific individuals",
                            "Phishing through phone calls"
                        ],
                        "correct": 2,
                        "explanation": "Spear phishing targets specific individuals using personalized information to appear more legitimate."
                    }
                ]
            },
            {
                "id": "password_security",
                "title": "Password Security Best Practices",
                "description": "Create and manage strong passwords effectively",
                "duration_minutes": 12,
                "category": "Account Security",
                "difficulty": "Beginner",
                "content": [
                    {
                        "type": "text",
                        "title": "Why Password Security Matters",
                        "content": """
Passwords are your first line of defense against unauthorized access. Weak or reused passwords are responsible for over 80% of data breaches.

**The Problem:**
- People use the same password for multiple accounts
- Simple passwords can be cracked in seconds
- Password breaches expose millions of credentials
"""
                    },
                    {
                        "type": "text",
                        "title": "Creating Strong Passwords",
                        "content": """
**Strong Password Characteristics:**
- At least 12 characters long (16+ is better)
- Mix of uppercase, lowercase, numbers, and symbols
- No personal information (birthdays, names, etc.)
- Not a common word or phrase

**Good Password Example:**
`Tr0ub4dor&3#Horse` (but don't use this one!)

**Better Approach - Passphrases:**
`correct-horse-battery-staple-42!`
Long, memorable, and very secure.
"""
                    },
                    {
                        "type": "text",
                        "title": "Password Managers",
                        "content": """
**Why Use a Password Manager?**
- Generates unique, strong passwords for every account
- Stores passwords securely encrypted
- Auto-fills credentials safely
- Alerts you to compromised passwords

**Popular Password Managers:**
- 1Password
- Bitwarden
- LastPass
- Dashlane

**You only need to remember ONE master password!**
"""
                    },
                    {
                        "type": "text",
                        "title": "Multi-Factor Authentication (MFA)",
                        "content": """
**What is MFA?**
An extra layer of security requiring something you know (password) AND something you have (phone, security key).

**Types of MFA:**
1. **SMS codes** - Sent to your phone (better than nothing)
2. **Authenticator apps** - Google Authenticator, Authy (more secure)
3. **Hardware keys** - YubiKey, Titan (most secure)

**Enable MFA on:**
- Email accounts
- Banking and financial services
- Social media
- Work applications
"""
                    }
                ],
                "quiz": [
                    {
                        "question": "What is the minimum recommended password length?",
                        "options": [
                            "6 characters",
                            "8 characters",
                            "12 characters",
                            "4 characters"
                        ],
                        "correct": 2,
                        "explanation": "Security experts recommend at least 12 characters, with 16+ being even better."
                    },
                    {
                        "question": "What is the best way to manage multiple unique passwords?",
                        "options": [
                            "Write them on sticky notes",
                            "Use the same password everywhere",
                            "Use a password manager",
                            "Store them in an unencrypted document"
                        ],
                        "correct": 2,
                        "explanation": "Password managers securely store unique passwords for all your accounts."
                    },
                    {
                        "question": "Which MFA method is considered most secure?",
                        "options": [
                            "SMS text messages",
                            "Email codes",
                            "Hardware security keys",
                            "Security questions"
                        ],
                        "correct": 2,
                        "explanation": "Hardware security keys provide the strongest protection against phishing and account takeover."
                    }
                ]
            },
            {
                "id": "social_engineering",
                "title": "Social Engineering Defense",
                "description": "Recognize and prevent manipulation tactics",
                "duration_minutes": 18,
                "category": "Human Security",
                "difficulty": "Intermediate",
                "content": [
                    {
                        "type": "text",
                        "title": "Understanding Social Engineering",
                        "content": """
Social engineering exploits human psychology rather than technical vulnerabilities. Attackers manipulate people into making security mistakes.

**Why It Works:**
- Desire to be helpful
- Trust in authority
- Fear of consequences
- Curiosity
- Urgency and pressure
"""
                    },
                    {
                        "type": "text",
                        "title": "Common Tactics",
                        "content": """
**1. Pretexting**
Creating a fabricated scenario to gain trust.
Example: "Hi, I'm from IT. We need your password to fix an issue."

**2. Baiting**
Offering something enticing to lure victims.
Example: USB drives left in parking lots with malware.

**3. Quid Pro Quo**
Offering a service in exchange for information.
Example: "Free tech support" that installs malware.

**4. Tailgating**
Following authorized personnel into secure areas.

**5. Intimidation**
Using authority or threats to pressure compliance.
"""
                    },
                    {
                        "type": "text",
                        "title": "Defense Strategies",
                        "content": """
**1. Verify Identity**
- Call back using official numbers
- Confirm requests through known channels
- Check with supervisors for unusual requests

**2. Slow Down**
- Don't let urgency override judgment
- Take time to verify before acting
- If it feels wrong, it probably is

**3. Protect Information**
- Never share passwords
- Be cautious with personal details
- Shred sensitive documents

**4. Report Suspicious Activity**
- Alert security team immediately
- Document the incident
- Help protect colleagues
"""
                    }
                ],
                "quiz": [
                    {
                        "question": "Someone calls claiming to be from IT and asks for your password. What should you do?",
                        "options": [
                            "Give them the password since they're from IT",
                            "Hang up and call IT directly to verify",
                            "Ask them to prove they're from IT",
                            "Give them a fake password"
                        ],
                        "correct": 1,
                        "explanation": "Always verify identity through official channels. Legitimate IT staff will never ask for your password."
                    },
                    {
                        "question": "What is 'tailgating' in security terms?",
                        "options": [
                            "Following someone closely on the highway",
                            "Following someone through a secure door",
                            "Sending follow-up phishing emails",
                            "Tracking someone's social media"
                        ],
                        "correct": 1,
                        "explanation": "Tailgating is when an unauthorized person follows an authorized person through a secure entrance."
                    }
                ]
            },
            {
                "id": "data_protection",
                "title": "Data Protection and Privacy",
                "description": "Handle sensitive data responsibly",
                "duration_minutes": 15,
                "category": "Data Security",
                "difficulty": "Intermediate",
                "content": [
                    {
                        "type": "text",
                        "title": "Types of Sensitive Data",
                        "content": """
**Personal Identifiable Information (PII):**
- Names, addresses, phone numbers
- Social Security numbers
- Driver's license numbers
- Financial information

**Protected Health Information (PHI):**
- Medical records
- Health insurance information
- Treatment history

**Business Confidential:**
- Trade secrets
- Financial data
- Customer information
- Strategic plans
"""
                    },
                    {
                        "type": "text",
                        "title": "Data Handling Best Practices",
                        "content": """
**1. Classify Data Properly**
- Understand what data you're handling
- Apply appropriate protection level

**2. Minimize Data Collection**
- Only collect what's necessary
- Don't retain data longer than needed

**3. Secure Storage**
- Encrypt sensitive files
- Use secure cloud storage
- Lock physical documents

**4. Safe Transmission**
- Use encrypted email for sensitive data
- Avoid public WiFi for confidential work
- Verify recipient before sending
"""
                    },
                    {
                        "type": "text",
                        "title": "Data Breach Response",
                        "content": """
**If You Suspect a Data Breach:**

1. **Don't Panic** - Stay calm and act quickly
2. **Don't Delete Evidence** - Preserve all information
3. **Report Immediately** - Contact IT/Security team
4. **Document Everything** - What happened, when, how discovered
5. **Contain the Breach** - Disconnect affected systems if instructed
6. **Cooperate with Investigation** - Provide all requested information
"""
                    }
                ],
                "quiz": [
                    {
                        "question": "Which of the following is considered PII?",
                        "options": [
                            "Company address",
                            "Product prices",
                            "Social Security number",
                            "Public press releases"
                        ],
                        "correct": 2,
                        "explanation": "Social Security numbers are Personal Identifiable Information that requires protection."
                    },
                    {
                        "question": "What should you do first if you discover a potential data breach?",
                        "options": [
                            "Delete all evidence",
                            "Report to IT/Security immediately",
                            "Try to fix it yourself",
                            "Wait to see if it gets worse"
                        ],
                        "correct": 1,
                        "explanation": "Immediately reporting allows the security team to respond quickly and minimize damage."
                    }
                ]
            },
            {
                "id": "remote_work_security",
                "title": "Secure Remote Work",
                "description": "Stay secure while working from home or traveling",
                "duration_minutes": 12,
                "category": "Remote Security",
                "difficulty": "Beginner",
                "content": [
                    {
                        "type": "text",
                        "title": "Remote Work Risks",
                        "content": """
Working remotely introduces unique security challenges:

- **Unsecured home networks**
- **Shared devices with family**
- **Public WiFi risks**
- **Physical security of devices**
- **Increased phishing attempts**
- **Shadow IT (unauthorized apps)**
"""
                    },
                    {
                        "type": "text",
                        "title": "Securing Your Home Network",
                        "content": """
**Router Security:**
1. Change default admin password
2. Use WPA3 or WPA2 encryption
3. Update router firmware regularly
4. Disable remote management

**Network Segmentation:**
- Create a separate network for work devices
- Keep IoT devices on guest network
- Use VPN for all work activities
"""
                    },
                    {
                        "type": "text",
                        "title": "Device Security",
                        "content": """
**Physical Security:**
- Lock screen when stepping away
- Don't leave devices unattended in public
- Use privacy screens in public spaces
- Secure home office when away

**Digital Security:**
- Keep software updated
- Use company-approved tools only
- Enable full disk encryption
- Regular backups
"""
                    },
                    {
                        "type": "text",
                        "title": "Public WiFi Safety",
                        "content": """
**Avoid Public WiFi When Possible**

If you must use it:
1. **Always use VPN** - Encrypts your traffic
2. **Verify network name** - Attackers create fake networks
3. **Disable auto-connect** - Prevent connecting to rogue networks
4. **Don't access sensitive accounts** - Banking, work systems
5. **Use mobile hotspot instead** - More secure than public WiFi
"""
                    }
                ],
                "quiz": [
                    {
                        "question": "What should you always use when connecting to public WiFi for work?",
                        "options": [
                            "Incognito mode",
                            "VPN",
                            "Faster browser",
                            "Guest account"
                        ],
                        "correct": 1,
                        "explanation": "A VPN encrypts your traffic, protecting your data even on unsecured networks."
                    },
                    {
                        "question": "What is a good practice when leaving your computer temporarily?",
                        "options": [
                            "Leave it on for convenience",
                            "Lock the screen",
                            "Close the lid without locking",
                            "Just minimize windows"
                        ],
                        "correct": 1,
                        "explanation": "Always lock your screen to prevent unauthorized access, even for brief absences."
                    }
                ]
            }
        ]

        return [TrainingModule(**m) for m in modules_data]

    def get_all_modules(self) -> List[Dict[str, Any]]:
        """Get all training modules"""
        return [
            {
                "id": m.id,
                "title": m.title,
                "description": m.description,
                "duration_minutes": m.duration_minutes,
                "category": m.category,
                "difficulty": m.difficulty
            }
            for m in self.modules
        ]

    def get_module(self, module_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific training module"""
        for m in self.modules:
            if m.id == module_id:
                return {
                    "id": m.id,
                    "title": m.title,
                    "description": m.description,
                    "duration_minutes": m.duration_minutes,
                    "category": m.category,
                    "difficulty": m.difficulty,
                    "content": m.content,
                    "quiz": m.quiz
                }
        return None

    def evaluate_quiz(self, module_id: str, answers: List[int]) -> Dict[str, Any]:
        """Evaluate quiz answers and return results"""
        module = None
        for m in self.modules:
            if m.id == module_id:
                module = m
                break

        if not module:
            return {"error": "Module not found"}

        quiz = module.quiz
        if len(answers) != len(quiz):
            return {"error": "Incorrect number of answers"}

        correct = 0
        results = []

        for i, (answer, question) in enumerate(zip(answers, quiz)):
            is_correct = answer == question["correct"]
            if is_correct:
                correct += 1

            results.append({
                "question": question["question"],
                "your_answer": question["options"][answer] if 0 <= answer < len(question["options"]) else "Invalid",
                "correct_answer": question["options"][question["correct"]],
                "is_correct": is_correct,
                "explanation": question["explanation"]
            })

        score = (correct / len(quiz)) * 100
        passed = score >= 70

        return {
            "module_id": module_id,
            "total_questions": len(quiz),
            "correct_answers": correct,
            "score": round(score, 1),
            "passed": passed,
            "results": results,
            "message": "Congratulations! You passed the quiz." if passed else "Please review the material and try again."
        }

    def get_categories(self) -> List[str]:
        """Get all training categories"""
        return list(set(m.category for m in self.modules))

    def get_modules_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get modules filtered by category"""
        return [
            {
                "id": m.id,
                "title": m.title,
                "description": m.description,
                "duration_minutes": m.duration_minutes,
                "difficulty": m.difficulty
            }
            for m in self.modules
            if m.category == category
        ]

    def calculate_progress(self, completed_modules: List[str]) -> Dict[str, Any]:
        """Calculate overall training progress"""
        total_modules = len(self.modules)
        completed = len([m for m in completed_modules if m in [mod.id for mod in self.modules]])

        total_minutes = sum(m.duration_minutes for m in self.modules)
        completed_minutes = sum(
            m.duration_minutes for m in self.modules
            if m.id in completed_modules
        )

        return {
            "total_modules": total_modules,
            "completed_modules": completed,
            "progress_percentage": round((completed / total_modules) * 100, 1) if total_modules > 0 else 0,
            "total_training_minutes": total_minutes,
            "completed_minutes": completed_minutes,
            "remaining_minutes": total_minutes - completed_minutes
        }
