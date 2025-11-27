#!/usr/bin/env python3
"""
Parse SSLscan XML output and extract IP addresses with SSL/TLS issues.

This script identifies hosts with:
- Weak ciphers (NULL, anon, EXPORT, DES, RC4, MD5)
- Outdated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- Certificate issues (expired, self-signed, weak signature)
- Compression enabled (CRIME vulnerability)
- Heartbleed vulnerability
- Other security concerns
"""

import xml.etree.ElementTree as ET
import argparse
import sys
from typing import List, Dict, Set
from collections import defaultdict

# ANSI COLORS
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Weak cipher patterns
WEAK_CIPHER_INDICATORS = [
    'NULL',
    'anon',
    'EXPORT',
    'DES',
    'RC4',
    'MD5',
    'RC2',
    'IDEA',
    '3DES',
    'CBC'  # CBC mode can be vulnerable to padding oracle attacks
]

# Insecure protocols
INSECURE_PROTOCOLS = [
    'SSLv2',
    'SSLv3',
    'TLSv1.0',
    'TLSv1.1'
]


class SSLIssue:
    """Represents an SSL/TLS security issue"""
    def __init__(self, severity: str, category: str, description: str):
        self.severity = severity  # critical, high, medium, low
        self.category = category
        self.description = description
    
    def __repr__(self):
        return f"{self.severity.upper()}: {self.category} - {self.description}"


class HostResult:
    """Stores results for a single host"""
    def __init__(self, host: str, port: str):
        self.host = host
        self.port = port
        self.issues: List[SSLIssue] = []
        self.enabled_protocols: List[str] = []
        self.weak_ciphers: List[Dict] = []
        self.certificate_issues: List[str] = []
        
    def add_issue(self, severity: str, category: str, description: str):
        self.issues.append(SSLIssue(severity, category, description))
    
    def has_issues(self) -> bool:
        return len(self.issues) > 0
    
    def get_severity_count(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for issue in self.issues:
            counts[issue.severity] += 1
        return counts


def parse_sslscan_xml(xml_file: str) -> List[HostResult]:
    """Parse SSLscan XML output and extract hosts with issues"""
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"{RED}[!] Error parsing XML file: {e}{RESET}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{RED}[!] File not found: {xml_file}{RESET}")
        sys.exit(1)
    
    results = []
    
    # SSLscan XML can have different structures depending on version
    # Try to find all ssltest elements
    for ssltest in root.findall('.//ssltest'):
        host = ssltest.get('host', 'unknown')
        port = ssltest.get('port', '443')
        
        result = HostResult(host, port)
        
        # Check for protocol issues
        for protocol in ssltest.findall('.//protocol'):
            protocol_type = protocol.get('type', '')
            protocol_version = protocol.get('version', '')
            enabled = protocol.get('enabled', '0')
            
            full_protocol = f"{protocol_type}v{protocol_version}"
            
            if enabled == '1':
                result.enabled_protocols.append(full_protocol)
                
                # Check if it's an insecure protocol
                if any(insecure in full_protocol for insecure in INSECURE_PROTOCOLS):
                    severity = 'critical' if 'SSLv' in full_protocol else 'high'
                    result.add_issue(
                        severity,
                        'Insecure Protocol',
                        f"{full_protocol} is enabled (deprecated and insecure)"
                    )
        
        # Check for cipher issues
        for cipher in ssltest.findall('.//cipher'):
            cipher_status = cipher.get('status', '')
            cipher_name = cipher.get('cipher', '')
            cipher_strength = cipher.get('bits', '')
            sslversion = cipher.get('sslversion', '')
            
            if cipher_status == 'accepted':
                # Check for weak ciphers
                is_weak = any(weak in cipher_name.upper() for weak in WEAK_CIPHER_INDICATORS)
                
                if is_weak:
                    result.weak_ciphers.append({
                        'name': cipher_name,
                        'strength': cipher_strength,
                        'protocol': sslversion
                    })
                    
                    # Determine severity
                    if any(x in cipher_name.upper() for x in ['NULL', 'ANON', 'EXPORT']):
                        severity = 'critical'
                    elif any(x in cipher_name.upper() for x in ['DES', 'RC4', 'MD5']):
                        severity = 'high'
                    else:
                        severity = 'medium'
                    
                    result.add_issue(
                        severity,
                        'Weak Cipher',
                        f"{cipher_name} ({cipher_strength} bits) on {sslversion}"
                    )
                
                # Check for low bit strength
                try:
                    bits = int(cipher_strength)
                    if bits < 128 and not is_weak:
                        result.add_issue(
                            'high',
                            'Weak Key Size',
                            f"{cipher_name} uses only {bits} bits"
                        )
                except (ValueError, TypeError):
                    pass
        
        # Check for certificate issues
        for cert in ssltest.findall('.//certificate'):
            # Check expiration
            not_valid_after = cert.find('.//not-valid-after')
            if not_valid_after is not None and not_valid_after.text:
                # Note: Proper date validation would require parsing the date
                pass
            
            # Check for self-signed
            self_signed = cert.find('.//self-signed')
            if self_signed is not None and self_signed.text == 'true':
                result.add_issue(
                    'medium',
                    'Certificate Issue',
                    'Certificate is self-signed'
                )
                result.certificate_issues.append('Self-signed')
            
            # Check signature algorithm
            signature_algorithm = cert.find('.//signature-algorithm')
            if signature_algorithm is not None:
                sig_alg = signature_algorithm.text or ''
                if 'md5' in sig_alg.lower() or 'sha1' in sig_alg.lower():
                    result.add_issue(
                        'high',
                        'Weak Certificate Signature',
                        f'Certificate uses weak signature algorithm: {sig_alg}'
                    )
                    result.certificate_issues.append(f'Weak signature: {sig_alg}')
        
        # Check for compression (CRIME vulnerability)
        compression = ssltest.find('.//compression')
        if compression is not None:
            supported = compression.get('supported', '0')
            if supported == '1':
                result.add_issue(
                    'medium',
                    'Compression Enabled',
                    'TLS compression is enabled (CRIME vulnerability)'
                )
        
        # Check for heartbleed
        heartbleed = ssltest.find('.//heartbleed')
        if heartbleed is not None:
            vulnerable = heartbleed.get('vulnerable', '0')
            if vulnerable == '1':
                result.add_issue(
                    'critical',
                    'Heartbleed',
                    'Server is vulnerable to Heartbleed (CVE-2014-0160)'
                )
        
        # Check for renegotiation issues
        renegotiation = ssltest.find('.//renegotiation')
        if renegotiation is not None:
            supported = renegotiation.get('supported', '0')
            secure = renegotiation.get('secure', '0')
            if supported == '1' and secure == '0':
                result.add_issue(
                    'medium',
                    'Insecure Renegotiation',
                    'Insecure renegotiation is supported'
                )
        
        # Only add hosts that have issues
        if result.has_issues():
            results.append(result)
    
    return results


def print_results(results: List[HostResult], output_format: str = 'detailed'):
    """Print results in specified format"""
    
    if not results:
        print(f"{GREEN}[+] No hosts with SSL/TLS issues found!{RESET}")
        return
    
    if output_format == 'ip-only':
        # Just print IP addresses
        print(f"{BOLD}Hosts with SSL/TLS Issues:{RESET}\n")
        for result in results:
            print(f"{result.host}:{result.port}")
    
    elif output_format == 'summary':
        # Print IPs with issue count
        print(f"{BOLD}Hosts with SSL/TLS Issues:{RESET}\n")
        for result in results:
            severity_counts = result.get_severity_count()
            critical = severity_counts.get('critical', 0)
            high = severity_counts.get('high', 0)
            medium = severity_counts.get('medium', 0)
            low = severity_counts.get('low', 0)
            
            issues_str = []
            if critical > 0:
                issues_str.append(f"{RED}{critical} critical{RESET}")
            if high > 0:
                issues_str.append(f"{RED}{high} high{RESET}")
            if medium > 0:
                issues_str.append(f"{YELLOW}{medium} medium{RESET}")
            if low > 0:
                issues_str.append(f"{CYAN}{low} low{RESET}")
            
            print(f"{result.host}:{result.port} - {', '.join(issues_str)}")
    
    else:  # detailed
        print(f"{BOLD}{'='*80}{RESET}")
        print(f"{BOLD}SSL/TLS VULNERABILITY REPORT{RESET}")
        print(f"{BOLD}{'='*80}{RESET}\n")
        print(f"Total hosts with issues: {RED}{BOLD}{len(results)}{RESET}\n")
        
        for result in results:
            print(f"{CYAN}{BOLD}{'─'*80}{RESET}")
            print(f"{CYAN}{BOLD}Host: {result.host}:{result.port}{RESET}")
            print(f"{CYAN}{BOLD}{'─'*80}{RESET}\n")
            
            # Group issues by severity
            critical_issues = [i for i in result.issues if i.severity == 'critical']
            high_issues = [i for i in result.issues if i.severity == 'high']
            medium_issues = [i for i in result.issues if i.severity == 'medium']
            low_issues = [i for i in result.issues if i.severity == 'low']
            
            if critical_issues:
                print(f"{RED}{BOLD}🔴 CRITICAL Issues:{RESET}")
                for issue in critical_issues:
                    print(f"  • {issue.category}: {issue.description}")
                print()
            
            if high_issues:
                print(f"{RED}{BOLD}🟠 HIGH Issues:{RESET}")
                for issue in high_issues:
                    print(f"  • {issue.category}: {issue.description}")
                print()
            
            if medium_issues:
                print(f"{YELLOW}{BOLD}🟡 MEDIUM Issues:{RESET}")
                for issue in medium_issues:
                    print(f"  • {issue.category}: {issue.description}")
                print()
            
            if low_issues:
                print(f"{CYAN}{BOLD}🔵 LOW Issues:{RESET}")
                for issue in low_issues:
                    print(f"  • {issue.category}: {issue.description}")
                print()
            
            # Show enabled protocols
            if result.enabled_protocols:
                print(f"{BOLD}Enabled Protocols:{RESET}")
                print(f"  {', '.join(result.enabled_protocols)}\n")
            
            print()
        
        print(f"{BOLD}{'='*80}{RESET}\n")
        
        # Summary statistics
        total_critical = sum(1 for r in results for i in r.issues if i.severity == 'critical')
        total_high = sum(1 for r in results for i in r.issues if i.severity == 'high')
        total_medium = sum(1 for r in results for i in r.issues if i.severity == 'medium')
        total_low = sum(1 for r in results for i in r.issues if i.severity == 'low')
        
        print(f"{BOLD}Summary:{RESET}")
        print(f"  Total Hosts with Issues: {len(results)}")
        print(f"  {RED}Critical Issues: {total_critical}{RESET}")
        print(f"  {RED}High Issues: {total_high}{RESET}")
        print(f"  {YELLOW}Medium Issues: {total_medium}{RESET}")
        print(f"  {CYAN}Low Issues: {total_low}{RESET}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Parse SSLscan XML output and find hosts with SSL/TLS issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f sslscan_output.xml
  %(prog)s -f sslscan_output.xml -o ip-only
  %(prog)s -f sslscan_output.xml -o summary > vulnerable_hosts.txt
  
Output formats:
  detailed  - Full report with all issues (default)
  summary   - IP addresses with issue counts
  ip-only   - Just IP:port (one per line)
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='SSLscan XML output file'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['detailed', 'summary', 'ip-only'],
        default='detailed',
        help='Output format (default: detailed)'
    )
    
    parser.add_argument(
        '--min-severity',
        choices=['critical', 'high', 'medium', 'low'],
        default='low',
        help='Minimum severity to report (default: low)'
    )
    
    args = parser.parse_args()
    
    # Parse the XML file
    results = parse_sslscan_xml(args.file)
    
    # Filter by severity if requested
    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    min_severity_value = severity_order[args.min_severity]
    
    filtered_results = []
    for result in results:
        # Check if any issue meets minimum severity
        has_qualifying_issue = any(
            severity_order[issue.severity] >= min_severity_value
            for issue in result.issues
        )
        if has_qualifying_issue:
            filtered_results.append(result)
    
    # Print results
    print_results(filtered_results, args.output)


if __name__ == "__main__":
    main()
