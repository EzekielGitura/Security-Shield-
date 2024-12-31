# core/detection_engine/content_inspector.py
import hashlib
import magic
import yara
from typing import Dict, List, BinaryIO
import re

class ContentInspector:
    def __init__(self, yara_rules_path: str = "rules/malware.yar"):
        self.mime_magic = magic.Magic(mime=True)
        try:
            self.yara_rules = yara.compile(yara_rules_path)
        except:
            print("Warning: YARA rules not loaded. Limited inspection available.")
            self.yara_rules = None
        
        self.suspicious_content_patterns = {
            'script_injection': [
                r'<script\b[^>]*>[\s\S]*?</script>',
                r'javascript:.*[(]',
                r'eval\s*\(['"\s]*'
            ],
            'sql_injection': [
                r'\bUNION\b.*\bSELECT\b',
                r';\s*DROP\s+TABLE',
                r'--\s*$'
            ],
            'xss': [
                r'<img[^>]+onerror=',
                r'<[^>]+onmouseover=',
                r'<[^>]+onload='
            ]
        }

    def inspect_content(self, content: bytes, filename: str = None) -> Dict[str, any]:
        """Inspect binary content for security threats."""
        result = {
            'is_malicious': False,
            'threat_types': [],
            'mime_type': None,
            'hashes': {},
            'matches': [],
            'risk_score': 0.0
        }

        # Calculate file hashes
        result['hashes'] = self._calculate_hashes(content)
        
        # Determine MIME type
        try:
            result['mime_type'] = self.mime_magic.from_buffer(content)
        except:
            result['threat_types'].append('mime_detection_failed')
            result['risk_score'] += 0.2

        # YARA scanning
        if self.yara_rules:
            matches = self.yara_rules.match(data=content)
            if matches:
                result['matches'].extend([str(match) for match in matches])
                result['threat_types'].append('yara_match')
                result['risk_score'] += 0.4

        # Content-specific inspection
        if result['mime_type']:
            self._inspect_by_mime_type(content, result)

        # Pattern matching for text content
        if self._is_text_content(result['mime_type']):
            self._check_patterns(content.decode('utf-8', errors='ignore'), result)

        # Final risk assessment
        result['is_malicious'] = result['risk_score'] >= 0.7
        return result

    def _calculate_hashes(self, content: bytes) -> Dict[str, str]:
        """Calculate multiple hashes of the content."""
        return {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest()
        }

    def _is_text_content(self, mime_type: str) -> bool:
        """Check if content is text-based."""
        return mime_type and (
            mime_type.startswith('text/') or
            mime_type in ['application/json', 'application/xml', 'application/javascript']
        )

    def _inspect_by_mime_type(self, content: bytes, result: Dict) -> None:
        """Perform MIME type specific inspection."""
        mime_handlers = {
            'application/pdf': self._inspect_pdf,
            'application/x-dosexec': self._inspect_executable,
            'application/zip': self._inspect_archive
        }

        mime_type = result['mime_type']
        handler = mime_handlers.get(mime_type)
        if handler:
            handler(content, result)

    def _check_patterns(self, text: str, result: Dict) -> None:
        """Check for suspicious patterns in text content."""
        for threat_type, patterns in self.suspicious_content_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    result['threat_types'].append(threat_type)
                    result['risk_score'] += 0.3

    def _inspect_pdf(self, content: bytes, result: Dict) -> None:
        """Inspect PDF content for common malicious patterns."""
        suspicious_patterns = [b'/JavaScript', b'/Launch', b'/OpenAction']
        for pattern in suspicious_patterns:
            if pattern in content:
                result['threat_types'].append('suspicious_pdf')
                result['risk_score'] += 0.3

    def _inspect_executable(self, content: bytes, result: Dict) -> None:
        """Inspect executable content."""
        result['threat_types'].append('executable')
        result['risk_score'] += 0.5

    def _inspect_archive(self, content: bytes, result: Dict) -> None:
        """Inspect archive content."""
        # Basic archive inspection
        if content.startswith(b'PK'):
            result['threat_types'].append('archive')
            result['risk_score'] += 0.1

# core/detection_engine/domain_validator.py
import dns.resolver
import whois
import requests
from typing import Dict, List, Optional
import time
import re

class DomainValidator:
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 3
        self.dns_resolver.lifetime = 3
        
        self.reputation_services = {
            'google_safebrowsing': 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
            'domain_blacklist': 'https://api.blacklist.com/v1/check',  # Example URL
        }
        
        self.suspicious_tld = {
            'high_risk': ['.tk', '.top', '.xyz', '.country', '.stream', '.gq', '.ml', '.cf'],
            'medium_risk': ['.info', '.site', '.online', '.biz', '.pw']
        }

    def validate_domain(self, domain: str) -> Dict[str, any]:
        """Validate a domain for potential security threats."""
        result = {
            'domain': domain,
            'is_valid': False,
            'risk_score': 0.0,
            'risk_factors': [],
            'dns_records': {},
            'whois_info': {},
            'reputation': {}
        }

        # Basic domain format validation
        if not self._is_valid_domain_format(domain):
            result['risk_factors'].append('Invalid domain format')
            return result

        # Perform checks
        self._check_dns_records(domain, result)
        self._check_whois_info(domain, result)
        self._check_reputation(domain, result)
        self._analyze_domain_characteristics(domain, result)

        # Calculate final risk score
        result['is_valid'] = len(result['risk_factors']) == 0
        return result

    def _is_valid_domain_format(self, domain: str) -> bool:
        """Check if domain format is valid."""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))

    def _check_dns_records(self, domain: str, result: Dict) -> None:
        """Check DNS records for the domain."""
        try:
            # Check A record
            a_records = self.dns_resolver.resolve(domain, 'A')
            result['dns_records']['a_records'] = [str(r) for r in a_records]

            # Check MX records
            try:
                mx_records = self.dns_resolver.resolve(domain, 'MX')
                result['dns_records']['mx_records'] = [str(r) for r in mx_records]
            except dns.resolver.NoAnswer:
                result['dns_records']['mx_records'] = []

            # Check NS records
            ns_records = self.dns_resolver.resolve(domain, 'NS')
            result['dns_records']['ns_records'] = [str(r) for r in ns_records]

        except dns.resolver.NXDOMAIN:
            result['risk_factors'].append('Domain does not exist')
            result['risk_score'] += 0.8
        except Exception as e:
            result['risk_factors'].append(f'DNS resolution error: {str(e)}')
            result['risk_score'] += 0.3

    def _check_whois_info(self, domain: str, result: Dict) -> None:
        """Check WHOIS information for the domain."""
        try:
            whois_info = whois.whois(domain)
            result['whois_info'] = {
                'registrar': whois_info.registrar,
                'creation_date': whois_info.creation_date,
                'expiration_date': whois_info.expiration_date,
                'last_updated': whois_info.updated_date
            }

            # Check domain age
            if whois_info.creation_date:
                creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
                domain_age = (time.time() - creation_date.timestamp()) / (24 * 3600)  # Age in days
                
                if domain_age < 30:
                    result['risk_factors'].append('Domain younger than 30 days')
                    result['risk_score'] += 0.4

        except Exception:
            result['risk_factors'].append('WHOIS lookup failed')
            result['risk_score'] += 0.2

    def _check_reputation(self, domain: str, result: Dict) -> None:
        """Check domain reputation using various services."""
        for service_name, api_url in self.reputation_services.items():
            try:
                response = requests.get(f"{api_url}?domain={domain}", timeout=5)
                if response.ok:
                    result['reputation'][service_name] = response.json()
                    if response.json().get('is_threat', False):
                        result['risk_factors'].append(f'Bad reputation: {service_name}')
                        result['risk_score'] += 0.5
            except:
                continue

    def _analyze_domain_characteristics(self, domain: str, result: Dict) -> None:
        """Analyze domain characteristics for suspicious patterns."""
        # Check TLD risk
        tld = domain.split('.')[-1].lower()
        if tld in self.suspicious_tld['high_risk']:
            result['risk_factors'].append('High-risk TLD')
            result['risk_score'] += 0.4
        elif tld in self.suspicious_tld['medium_risk']:
            result['risk_factors'].append('Medium-risk TLD')
            result['risk_score'] += 0.2

        # Check for suspicious patterns
        suspicious_patterns = [
            (r'\d{5,}', 'Contains many numbers'),
            (r'[.-]{2,}', 'Contains consecutive dots or hyphens'),
            (r'[a-zA-Z0-9]-[a-zA-Z0-9].*[a-zA-Z0-9]-[a-zA-Z0-9]', 'Multiple hyphens')
        ]

        for pattern, description in suspicious_patterns:
            if re.search(pattern, domain):
                result['risk_factors'].append(description)
                result['risk_score'] += 0.1
