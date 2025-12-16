"""
Basic URL Analyzer - Version 1.0
Simple but functional phishing URL detector
"""

import re
import requests
from urllib.parse import urlparse
from datetime import datetime

class BasicURLAnalyzer:
    def __init__(self):
        print("🔧 Basic URL Analyzer initialized!")
        self.suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'banking',
            'update', 'password', 'confirm', 'urgent', 'immediate'
        ]
    
    def analyze(self, url):
        """Analyze a URL for basic phishing indicators"""
        print(f"🔍 Analyzing: {url}")
        
        results = {
            'url': url,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'risk_score': 0,
            'verdict': 'Clean',
            'findings': []
        }
        
        # 1. Check URL length
        if len(url) > 75:
            results['risk_score'] += 10
            results['findings'].append("URL is unusually long (potential obfuscation)")
        
        # 2. Check for IP address in URL
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            results['risk_score'] += 20
            results['findings'].append("IP address found in URL (suspicious)")
        
        # 3. Check for @ symbol (userinfo - rare in legitimate URLs)
        if '@' in url:
            results['risk_score'] += 15
            results['findings'].append("@ symbol found (possible credential embedding)")
        
        # 4. Check for suspicious keywords
        url_lower = url.lower()
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                found_keywords.append(keyword)
                results['risk_score'] += 5
        
        if found_keywords:
            results['findings'].append(f"Suspicious keywords found: {', '.join(found_keywords)}")
        
        # 5. Check if HTTPS is used
        if url.startswith('http://'):  # Only penalize HTTP, not URLs without protocol
            results['risk_score'] += 5
            results['findings'].append("Using HTTP instead of HTTPS (less secure)")
        elif not url.startswith(('http://', 'https://')):
            results['risk_score'] += 3
            results['findings'].append("No protocol specified (adding https://)")
            url = 'https://' + url
            results['url'] = url
        
        # 6. Try to get page title (if accessible)
        try:
            response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                # Simple title extraction
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                if title_match:
                    results['page_title'] = title_match.group(1)
                    # Check title for suspicious words
                    title_lower = results['page_title'].lower()
                    if any(keyword in title_lower for keyword in ['login', 'verify', 'secure']):
                        results['risk_score'] += 10
                        results['findings'].append("Suspicious words in page title")
        except:
            results['findings'].append("Could not fetch page content")
        
        # Determine final verdict
        if results['risk_score'] >= 30:
            results['verdict'] = 'HIGH RISK ⚠️'
        elif results['risk_score'] >= 15:
            results['verdict'] = 'Suspicious'
        else:
            results['verdict'] = 'Clean ✅'
        
        return results
    
    def generate_report(self, analysis_results):
        """Generate a simple text report"""
        report = f"""
{'='*50}
PHISHGUARD URL ANALYSIS REPORT
{'='*50}
URL: {analysis_results['url']}
Time: {analysis_results['timestamp']}
Final Verdict: {analysis_results['verdict']}
Risk Score: {analysis_results['risk_score']}/100

FINDINGS:
"""
        for finding in analysis_results['findings']:
            report += f"• {finding}\n"
        
        if 'page_title' in analysis_results:
            report += f"\nPage Title: {analysis_results['page_title']}\n"
        
        report += f"\n{'='*50}\n"
        return report

# Test the analyzer
if __name__ == "__main__":
    print("🧪 Testing Basic URL Analyzer...")
    analyzer = BasicURLAnalyzer()
    
    # Test with a known safe URL
    test_url = "https://github.com"
    results = analyzer.analyze(test_url)
    
    print(analyzer.generate_report(results))
