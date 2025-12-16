#!/usr/bin/env python3
"""
PhishGuard Command Line Interface
Run: python3 phishguard_cli.py --url https://example.com
"""

import argparse
from modules.url_analyzer.basic_analyzer import BasicURLAnalyzer
import json

def main():
    parser = argparse.ArgumentParser(description='PhishGuard URL Analyzer')
    parser.add_argument('--url', help='URL to analyze')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--test', action='store_true', help='Run test cases')
    
    args = parser.parse_args()
    
    analyzer = BasicURLAnalyzer()
    
    if args.test:
        print("🧪 Running test cases...")
        test_urls = [
            "https://github.com",
            "http://test.com@malicious.com",
            "http://192.168.1.1/login.php",
            "https://paypal-verify-account.com"
        ]
        
        for test_url in test_urls:
            print(f"\n{'='*60}")
            print(f"Testing: {test_url}")
            results = analyzer.analyze(test_url)
            print(analyzer.generate_report(results))
    
    elif args.url:
        results = analyzer.analyze(args.url)
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(analyzer.generate_report(results))
    
    else:
        print("Please provide a URL to analyze")
        print("Usage: python3 phishguard_cli.py --url https://example.com")
        print("       python3 phishguard_cli.py --test (for test cases)")

if __name__ == "__main__":
    main()
