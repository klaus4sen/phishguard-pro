"""
Simple Email Analyzer - Detects phishing emails
"""

import re
import hashlib
from datetime import datetime

class SimpleEmailAnalyzer:
    def __init__(self):
        self.phishing_patterns = {
            'urgency': r'\b(urgent|immediate|action required|last warning)\b',
            'financial': r'\b(payment|invoice|bill|transfer|refund)\b',
            'threat': r'\b(suspended|closed|terminated|locked)\b',
            'request': r'\b(click here|verify now|update immediately)\b'
        }
    
    def analyze(self, email_text):
        """Analyze email content for phishing indicators"""
        print(f"📧 Analyzing email...")
        
        results = {
            'email_hash': hashlib.sha256(email_text.encode()).hexdigest()[:16],
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'risk_score': 0,
            'verdict': 'Clean',
            'findings': [],
            'links_found': [],
            'patterns_found': []
        }
        
        email_lower = email_text.lower()
        
        # 1. Check for phishing patterns
        for pattern_name, pattern in self.phishing_patterns.items():
            matches = re.findall(pattern, email_lower, re.IGNORECASE)
            if matches:
                results['risk_score'] += len(matches) * 10
                results['patterns_found'].append(f"{pattern_name}: {len(matches)} instances")
        
        # 2. Extract URLs from email
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        links = re.findall(url_pattern, email_text)
        results['links_found'] = links
        
        if links:
            results['risk_score'] += len(links) * 5
            results['findings'].append(f"Found {len(links)} URLs in email")
        
        # 3. Check for mismatched sender (basic)
        from_pattern = r'From:\s*(.+)'
        reply_pattern = r'Reply-To:\s*(.+)'
        
        from_match = re.search(from_pattern, email_text, re.IGNORECASE)
        reply_match = re.search(reply_pattern, email_text, re.IGNORECASE)
        
        if from_match and reply_match:
            if from_match.group(1) != reply_match.group(1):
                results['risk_score'] += 15
                results['findings'].append("From and Reply-To addresses don't match")
        
        # 4. Check for generic greetings
        greeting_pattern = r'Dear (Customer|User|Valued Member|Account Holder)'
        if re.search(greeting_pattern, email_text, re.IGNORECASE):
            results['risk_score'] += 10
            results['findings'].append("Generic greeting used")
        
        # Determine verdict
        if results['risk_score'] >= 40:
            results['verdict'] = 'HIGH RISK - Likely Phishing ⚠️'
        elif results['risk_score'] >= 20:
            results['verdict'] = 'Suspicious'
        else:
            results['verdict'] = 'Clean ✅'
        
        return results
    
    def generate_report(self, analysis_results):
        """Generate email analysis report"""
        report = f"""
{'='*60}
EMAIL ANALYSIS REPORT
{'='*60}
Email Hash: {analysis_results['email_hash']}
Time: {analysis_results['timestamp']}
Verdict: {analysis_results['verdict']}
Risk Score: {analysis_results['risk_score']}/100

PATTERNS DETECTED:
"""
        for pattern in analysis_results['patterns_found']:
            report += f"• {pattern}\n"
        
        report += f"\nFINDINGS:\n"
        for finding in analysis_results['findings']:
            report += f"• {finding}\n"
        
        if analysis_results['links_found']:
            report += f"\nURLS FOUND ({len(analysis_results['links_found'])}):\n"
            for i, link in enumerate(analysis_results['links_found'][:5], 1):
                report += f"{i}. {link}\n"
            if len(analysis_results['links_found']) > 5:
                report += f"... and {len(analysis_results['links_found']) - 5} more\n"
        
        report += f"\n{'='*60}\n"
        return report

# Test function
if __name__ == "__main__":
    print("🧪 Testing Email Analyzer...")
    
    test_email = """From: "Amazon Security" <security@amazon-verify.com>
Reply-To: support@amazon-support-urgent.net
Subject: Urgent: Your Account Will Be Suspended

Dear Customer,

We detected unusual activity on your Amazon account. 
Your account will be suspended unless you verify your information immediately.

Click here to verify: http://amazon-verify-account.com/login
This is urgent - please act now!

Best regards,
Amazon Security Team
"""
    
    analyzer = SimpleEmailAnalyzer()
    results = analyzer.analyze(test_email)
    print(analyzer.generate_report(results))
