# core/detection_engine/url_analyzer.py
import re
import requests
from typing import Dict, List, Optional
from urllib.parse import urlparse

class URLAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            r'(?:https?://)?(?:[^/\s]+\.)*(?:bit\.ly|tinyurl\.com|goo\.gl)(?:/[^\s]*)?',
            r'(?:[^/\s]+\.)*(?:\d{1,3}\.){3}\d{1,3}(?:/[^\s]*)?',
            r'(?:https?://)[^/\s]+\.(?:xyz|tk|pw|cc|fun|kim|party|download)(?:/[^\s]*)?'
        ]
        self.whitelist = set()
        self.blacklist = set()

    def load_lists(self, whitelist_path: str, blacklist_path: str) -> None:
        """Load whitelist and blacklist from files."""
        try:
            with open(whitelist_path, 'r') as f:
                self.whitelist = set(line.strip() for line in f)
            with open(blacklist_path, 'r') as f:
                self.blacklist = set(line.strip() for line in f)
        except FileNotFoundError:
            print("Warning: List files not found. Using empty lists.")

    def analyze_url(self, url: str) -> Dict[str, any]:
        """Analyze a URL for potential security threats."""
        result = {
            'url': url,
            'is_malicious': False,
            'risk_factors': [],
            'risk_score': 0.0,
            'analysis_details': {}
        }

        # Parse the URL
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
        except Exception:
            result['is_malicious'] = True
            result['risk_factors'].append('Invalid URL format')
            return result

        # Check blacklist/whitelist
        if domain in self.blacklist:
            result['is_malicious'] = True
            result['risk_factors'].append('Domain in blacklist')
            result['risk_score'] = 1.0
            return result
        
        if domain in self.whitelist:
            return result

        # Check suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                result['risk_factors'].append(f'Suspicious pattern match: {pattern}')
                result['risk_score'] += 0.3

        # Additional checks
        self._check_ssl(url, result)
        self._check_domain_age(domain, result)
        self._analyze_redirect_chain(url, result)

        # Final risk assessment
        result['is_malicious'] = result['risk_score'] >= 0.7
        return result

    def _check_ssl(self, url: str, result: Dict) -> None:
        """Check SSL certificate validity."""
        try:
            response = requests.get(url, verify=True, timeout=5)
            if not response.ok:
                result['risk_factors'].append('SSL verification failed')
                result['risk_score'] += 0.2
        except:
            result['risk_factors'].append('SSL check failed')
            result['risk_score'] += 0.1

    def _check_domain_age(self, domain: str, result: Dict) -> None:
        """Check domain registration age."""
        # Implementation would typically use WHOIS lookup
        pass

    def _analyze_redirect_chain(self, url: str, result: Dict) -> None:
        """Analyze URL redirect chain."""
        try:
            response = requests.get(url, allow_redirects=True, timeout=5)
            if len(response.history) > 2:
                result['risk_factors'].append(f'Multiple redirects: {len(response.history)}')
                result['risk_score'] += 0.2
        except:
            result['risk_factors'].append('Redirect analysis failed')
            result['risk_score'] += 0.1

# core/detection_engine/email_scanner.py
import re
from typing import Dict, List, Optional
from email.parser import Parser
from email.policy import default

class EmailScanner:
    def __init__(self):
        self.suspicious_patterns = {
            'phishing': [
                r'(?i)verify.*account',
                r'(?i)update.*payment.*information',
                r'(?i)unusual.*activity'
            ],
            'spam': [
                r'(?i)win.*prize',
                r'(?i)lottery.*winner',
                r'(?i)million.*dollars'
            ],
            'malware': [
                r'(?i)attachment.*important',
                r'(?i)invoice.*attached',
                r'(?i)resume.*attached'
            ]
        }

    def scan_email(self, email_content: str) -> Dict[str, any]:
        """Scan email content for potential threats."""
        result = {
            'is_threat': False,
            'threat_type': [],
            'confidence_score': 0.0,
            'detected_patterns': [],
            'metadata': {}
        }

        # Parse email
        email_parser = Parser(policy=default)
        parsed_email = email_parser.parsestr(email_content)

        # Extract metadata
        result['metadata'] = {
            'subject': parsed_email['subject'],
            'from': parsed_email['from'],
            'to': parsed_email['to'],
            'date': parsed_email['date']
        }

        # Analyze headers
        self._analyze_headers(parsed_email, result)
        
        # Analyze content
        self._analyze_content(parsed_email, result)
        
        # Check attachments
        self._analyze_attachments(parsed_email, result)

        return result

    def _analyze_headers(self, email: Parser, result: Dict) -> None:
        """Analyze email headers for suspicious patterns."""
        headers = dict(email.items())
        
        # Check for spoofed headers
        if 'X-Original-From' in headers or 'X-Originating-IP' in headers:
            result['threat_type'].append('potential_spoofing')
            result['confidence_score'] += 0.3

        # Check for bulk mail indicators
        bulk_headers = ['List-Unsubscribe', 'Precedence: bulk', 'X-Marketing']
        if any(h in headers for h in bulk_headers):
            result['threat_type'].append('bulk_mail')
            result['confidence_score'] += 0.1

    def _analyze_content(self, email: Parser, result: Dict) -> None:
        """Analyze email content for suspicious patterns."""
        content = email.get_payload(decode=True).decode() if email.is_multipart() else email.get_payload()

        for threat_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result['detected_patterns'].append(pattern)
                    result['threat_type'].append(threat_type)
                    result['confidence_score'] += 0.2

    def _analyze_attachments(self, email: Parser, result: Dict) -> None:
        """Analyze email attachments for potential threats."""
        if email.is_multipart():
            for part in email.walk():
                if part.get_content_maintype() == 'application':
                    filename = part.get_filename()
                    if filename:
                        if self._is_suspicious_attachment(filename):
                            result['threat_type'].append('suspicious_attachment')
                            result['confidence_score'] += 0.4

    def _is_suspicious_attachment(self, filename: str) -> bool:
        """Check if attachment filename is suspicious."""
        suspicious_extensions = {'.exe', '.bat', '.cmd', '.scr', '.js', '.vbs'}
        return any(filename.lower().endswith(ext) for ext in suspicious_extensions)
