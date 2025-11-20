import requests
import ssl
import socket
import datetime
import os
import time
from urllib.parse import urlparse
from collections import defaultdict
from requests.adapters import HTTPAdapter # Required for retries/session config

# --- CONFIGURATION ---
TIMEOUT = 7  # Max seconds to wait for a connection/response
DAYS_WARNING_THRESHOLD = 30 # Days left before SSL expiry triggers a WARNING
EXPECTED_SECURITY_HEADERS = [
    "Strict-Transport-Security", 
    "X-Frame-Options", 
    "Content-Security-Policy", 
    "X-Content-Type-Options",
    "Referrer-Policy"
]
MAX_RETRIES = 3
INITIAL_BACKOFF = 1

# --- PROXY CONFIGURATION ---
# Removed default Tor setting. Use an empty dict for direct connection.
# If connection fails again, manually re-insert proxy settings here.
PROXY_SETTINGS = {}

# Standard browser User-Agent
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36'
}

# Dictionary of potentially weak protocols to test for passively.
WEAK_PROTOCOLS = {
    'TLSv1': ssl.PROTOCOL_TLSv1, 
    'TLSv1.1': ssl.PROTOCOL_TLSv1_1
}

# --------------------------------------------------------------------------
# REFINEMENT 3: Using a requests.Session for more natural, persistent scanning
# --------------------------------------------------------------------------

def exponential_backoff_fetch(url, session, method='HEAD', max_retries=MAX_RETRIES, initial_backoff=INITIAL_BACKOFF, headers=None):
    """
    Performs an HTTP request using a persistent session with exponential backoff.
    """
    if headers is None:
        headers = REQUEST_HEADERS
        
    for attempt in range(max_retries):
        try:
            # Use the session for the request, which maintains connection pools and cookies
            if method == 'HEAD':
                response = session.head(url, timeout=TIMEOUT, allow_redirects=True, headers=headers, proxies=PROXY_SETTINGS) 
            else:
                response = session.get(url, timeout=TIMEOUT, allow_redirects=True, headers=headers, proxies=PROXY_SETTINGS) 
            return response
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                delay = initial_backoff * (2 ** attempt)
                time.sleep(delay)
            else:
                return None 
    return None

def check_http_details(url, session):
    """Fetches HTTP details, checks headers, status codes, and redirects using the shared session."""
    report = {
        'url': url,
        'status': 'FAIL',
        'status_code': 'N/A',
        'server': 'N/A',
        'tech_stack': 'N/A',
        'missing_headers': [],
        'redirects': 'No Redirect',
        'content_issue': 'None',
        'content_type': 'N/A'
    }
    
    try:
        # Pass the session object here
        response = exponential_backoff_fetch(url, session, method='GET')
        
        if not response:
            report['content_issue'] = "CRITICAL: Connection Failed after max retries (Possible WAF/Firewall block or host offline)."
            raise requests.exceptions.RequestException("Max retries exceeded or connection failed.")

        report['status_code'] = response.status_code
        report['status'] = 'OK' if 200 <= response.status_code < 400 else 'ISSUE'
        
        headers = response.headers
        report['server'] = headers.get('Server', 'Not Exposed')
        report['tech_stack'] = headers.get('X-Powered-By', 'Not Exposed')
        report['content_type'] = headers.get('Content-Type', 'N/A').split(';')[0].strip()
        
        # Check security headers
        for header in EXPECTED_SECURITY_HEADERS:
            if header not in headers:
                report['missing_headers'].append(header)

        # Check for broken pages
        if response.status_code == 404:
            report['content_issue'] = 'CRITICAL: 404 Not Found'
        elif 500 <= response.status_code < 600:
            report['content_issue'] = f'CRITICAL: {response.status_code} Server Error'
        
        # Check for redirects
        if response.history:
            report['redirects'] = f"Found {len(response.history)} redirects ({response.history[0].status_code} -> {response.status_code}), Final URL: {response.url}"
            
    except requests.exceptions.RequestException as e:
        report['status'] = 'ERROR'
        if report['content_issue'] == 'None':
             report['content_issue'] = f"Request Failed: {e}"
        
    return report

# SSL check functions remain unchanged as they use direct socket connections (bypassing requests/proxy)

def check_ssl_protocol_support(hostname, port, protocol):
    """Helper function to test if a specific SSL protocol is supported."""
    try:
        context = ssl.SSLContext(protocol)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except (ssl.SSLError, ConnectionRefusedError, socket.timeout):
        return False
    except Exception:
        return False

def check_ssl_details(url):
    """Gathers SSL/TLS certificate information and checks for weak protocols."""
    report = {
        'expiry_date': 'N/A',
        'days_remaining': 'N/A',
        'status': 'N/A',
        'tls_version': 'N/A',
        'issued_to': 'N/A',
        'san_match': 'N/A',
        'weak_protocols': [],
        'error': None
    }
    
    hostname = urlparse(url).netloc
    port = 443
    if not hostname:
        report['error'] = 'Invalid URL format or missing hostname.'
        return report

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_info = ssock.getpeercert()
                
                for subject_tuple in cert_info['subject']:
                    for key, value in subject_tuple:
                        if key == 'commonName':
                            report['issued_to'] = value
                            break
                
                san_match = False
                if 'subjectAltName' in cert_info:
                    for type, name in cert_info['subjectAltName']:
                        if type == 'DNS':
                            if name == hostname or (name.startswith('*') and hostname.endswith(name[1:])):
                                san_match = True
                                break
                
                if san_match:
                    report['san_match'] = 'PASS (SAN Match)'
                elif report['issued_to'] == hostname:
                     report['san_match'] = 'PASS (CN Only - Deprecated)'
                else:
                    report['san_match'] = 'CRITICAL: FAIL (Domain Mismatch)'

                expiry_date_str = cert_info['notAfter']
                expiry_date = datetime.datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                
                now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                expiry_date_naive = expiry_date.replace(tzinfo=None)
                
                time_difference = expiry_date_naive - now
                days_until_expiry = time_difference.days

                report['expiry_date'] = expiry_date_naive.strftime('%Y-%m-%d %H:%M UTC')
                report['days_remaining'] = days_until_expiry
                report['tls_version'] = ssock.version()
                report['status'] = 'OK'

                if days_until_expiry < 0:
                    report['status'] = 'CRITICAL: EXPIRED'
                elif days_until_expiry < DAYS_WARNING_THRESHOLD:
                    report['status'] = f'WARNING: Expires in {days_until_expiry} days'
        
    except socket.gaierror:
        report['error'] = 'DNS Resolution Failed or Invalid Hostname.'
    except ssl.SSLError as e:
        report['error'] = f'SSL/TLS Handshake Failed (e.g., untrusted cert, weak configuration): {e}'
    except Exception as e:
        report['error'] = f'Connection Error (Host might not support HTTPS on 443): {e}'

    if not report['error']:
        for protocol_name, protocol_const in WEAK_PROTOCOLS.items():
            if check_ssl_protocol_support(hostname, port, protocol_const):
                report['weak_protocols'].append(protocol_name)

    return report

def check_fingerprint(url, http_data, session):
    """
    Passively checks page content and headers for common CMS/technology signatures.
    """
    cms_signatures = {
        'WordPress': ['wp-content', 'wp-includes', 'WordPress'],
        'Joomla': ['/media/system/js/core.js', 'Joomla!'],
        'Drupal': ['/sites/default/files', 'Drupal'],
    }
    
    fingerprint = []

    # 1. Check Content (Only do this for successful HTML requests)
    if http_data['status'] == 'OK' and http_data['content_type'].startswith('text/html'):
        try:
            # Pass the session object here
            response = exponential_backoff_fetch(url, session, method='GET')
            if response and response.text:
                content = response.text
                
                for cms, signatures in cms_signatures.items():
                    if any(sig in content for sig in signatures):
                        fingerprint.append(cms)

        except requests.exceptions.RequestException:
            pass 

    # 2. Check for specific common metadata files
    robots_url = urlparse(url)._replace(path='/robots.txt').geturl()
    try:
        # Pass the session object here
        robots_response = exponential_backoff_fetch(robots_url, session, method='HEAD')
        if robots_response and robots_response.status_code == 200:
             fingerprint.append("robots.txt exposed (Review content)")
    except requests.exceptions.RequestException:
        pass 

    return list(set(fingerprint))

def generate_report_card(url, http_data, ssl_data, fingerprint_data):
    """Formats and prints the consolidated report card."""
    print("\n" + "="*80)
    print(f"🌐 REPORT CARD: {url}")
    print("="*80)

    is_failed_scan = http_data['status'] in ['ERROR', 'FAIL']

    # --- HTTP & CONTENT CHECK ---
    print("\n[ HTTP & CONTENT HEALTH ]")
    print("-" * 30)
    print(f"Status Code:    {http_data['status_code']}")
    print(f"Content Issue:  {http_data['content_issue']}")
    print(f"Redirects:      {http_data['redirects']}")
    print(f"Content Type:   {http_data['content_type']}")

    # --- TECH STACK & FINGERPRINTING ---
    print("\n[ TECH STACK & FINGERPRINTING ]")
    print("-" * 30)
    if is_failed_scan:
        print("Data:           UNKNOWN (HTTP Scan Failed)")
    else:
        print(f"Server Type:    {http_data['server']}")
        print(f"Tech Stack:     {http_data['tech_stack']}")
        if fingerprint_data:
            print(f"Inferred CMS/Tech: {', '.join(fingerprint_data)}")
        else:
            print("Inferred CMS/Tech: Not detected (minimal exposure)")

    # --- SECURITY HEADERS ---
    print("\n[ SECURITY HEADERS ]")
    print("-" * 30)
    if is_failed_scan:
        print("GRADE: UNKNOWN (HTTP Connection Failed)")
    elif http_data['missing_headers']:
        print(f"GRADE: DANGER ({len(http_data['missing_headers'])} missing)")
        for header in http_data['missing_headers']:
            print(f"  ❌ Missing: {header}")
    else:
        print("GRADE: EXCELLENT (All standard security headers found)")

    # --- SSL/TLS CONFIGURATION ---
    print("\n[ SSL/TLS CONFIGURATION ]")
    print("-" * 30)
    
    if ssl_data.get('error'):
        print(f"STATUS: FAILURE - {ssl_data['error']}")
    else:
        print(f"STATUS: {ssl_data['status']}")
        print(f"Issued To (CN): {ssl_data['issued_to']}")
        print(f"SAN Match: {ssl_data['san_match']}")
        print(f"Expiry Date: {ssl_data['expiry_date']}")
        print(f"Days Remaining: {ssl_data['days_remaining']}")
        print(f"Negotiated TLS: {ssl_data['tls_version']}")
        
        if ssl_data.get('weak_protocols'):
             print(f"⚠️ WEAK PROTOCOLS SUPPORTED: {', '.join(ssl_data['weak_protocols'])}")
        else:
             print("Weak Protocols: None detected.")
    
    print("="*80)

def main():
    """Main function to load targets, initialize session, and run the scanner."""
    targets_file = 'targets.txt'
    
    if not os.path.exists(targets_file):
        print(f"Error: Required file '{targets_file}' not found. Please create it and list URLs.")
        return

    # Initialize a global requests session
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)

    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not targets:
        print(f"Warning: '{targets_file}' is empty. Add URLs to scan.")
        return

    print(f"Starting passive scan of {len(targets)} targets...")
    for target_url in targets:
        if not target_url.startswith('http'):
             target_url = f"https://{target_url}" 

        print(f"\nScanning: {target_url}...")
        
        # 1. Run HTTP and Content Checks (passing the session)
        http_data = check_http_details(target_url, session)
        
        # 2. Run Fingerprint Check (passing the session)
        fingerprint_data = []
        if http_data['status'] in ['OK', 'ISSUE']:
            fingerprint_data = check_fingerprint(target_url, http_data, session)
        
        # 3. Run SSL/TLS Checks (direct socket connection, no session needed)
        ssl_data = {}
        if target_url.lower().startswith('https'):
            ssl_data = check_ssl_details(target_url)
        else:
            ssl_data['error'] = 'Skipped SSL check for HTTP URL.'
            
        # 4. Generate Report Card
        generate_report_card(target_url, http_data, ssl_data, fingerprint_data)

if __name__ == '__main__':
    main()
