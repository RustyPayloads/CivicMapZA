import requests
import ssl
import socket
import datetime
import os
import time
from urllib.parse import urlparse

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

def exponential_backoff_fetch(url, method='HEAD', max_retries=MAX_RETRIES, initial_backoff=INITIAL_BACKOFF):
    """
    Performs an HTTP request with exponential backoff for resilience.
    Uses 'HEAD' for efficiency or 'GET' if redirects need to be fully resolved.
    """
    for attempt in range(max_retries):
        try:
            if method == 'HEAD':
                response = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
            else:
                response = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
            return response
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                delay = initial_backoff * (2 ** attempt)
                print(f"    [Retry] Attempt {attempt + 1} failed for {url}. Retrying in {delay}s...")
                time.sleep(delay)
            else:
                raise e
    return None

def check_http_details(url):
    """Fetches HTTP details, checks headers, status codes, and redirects."""
    report = {
        'url': url,
        'status': 'FAIL',
        'status_code': 'N/A',
        'server': 'N/A',
        'tech_stack': 'N/A',
        'missing_headers': [],
        'redirects': 'No Redirect',
        'content_issue': 'None'
    }
    
    try:
        # Use a GET request to fully resolve redirects and content issues
        response = exponential_backoff_fetch(url, method='GET')
        
        if not response:
            raise requests.exceptions.RequestException("Max retries exceeded or connection failed.")

        report['status_code'] = response.status_code
        report['status'] = 'OK' if 200 <= response.status_code < 400 else 'ISSUE'
        
        headers = response.headers
        report['server'] = headers.get('Server', 'Not Exposed')
        report['tech_stack'] = headers.get('X-Powered-By', 'Not Exposed')
        
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
            report['redirects'] = f"Found {len(response.history)} redirects, Final URL: {response.url}"
            # Check for permanent redirects (301) vs temporary (302) if needed for hygiene
            
    except requests.exceptions.RequestException as e:
        report['status'] = 'ERROR'
        report['content_issue'] = f"Request Failed: {e}"
        
    return report

def check_ssl_details(url):
    """Gathers SSL/TLS certificate information."""
    report = {
        'expiry_date': 'N/A',
        'days_remaining': 'N/A',
        'status': 'N/A',
        'tls_version': 'N/A',
        'issued_to': 'N/A',
        'error': None
    }
    
    hostname = urlparse(url).netloc
    if not hostname:
        report['error'] = 'Invalid URL format or missing hostname.'
        return report

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_info = ssock.getpeercert()
                
                # Extract subject (CN)
                for subject_tuple in cert_info['subject']:
                    for key, value in subject_tuple:
                        if key == 'commonName':
                            report['issued_to'] = value
                            break

                expiry_date_str = cert_info['notAfter']
                # Common format is 'Dec 31 23:59:59 2025 GMT'
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
        report['error'] = f'SSL/TLS Handshake Failed (e.g., untrusted cert, weak ciphers): {e}'
    except Exception as e:
        report['error'] = f'Connection Error (Host might not support HTTPS on 443): {e}'

    return report

def generate_report_card(url, http_data, ssl_data):
    """Formats and prints the consolidated report card."""
    print("\n" + "="*80)
    print(f"🌐 REPORT CARD: {url}")
    print("="*80)

    # --- HTTP & CONTENT CHECK ---
    print("\n[ HTTP & CONTENT HEALTH ]")
    print("-" * 30)
    print(f"Status Code:    {http_data['status_code']}")
    print(f"Content Issue:  {http_data['content_issue']}")
    print(f"Redirects:      {http_data['redirects']}")
    print(f"Server Type:    {http_data['server']}")
    print(f"Tech Stack:     {http_data['tech_stack']}")

    # --- SECURITY HEADERS ---
    print("\n[ SECURITY HEADERS ]")
    print("-" * 30)
    if http_data['missing_headers']:
        print(f"GRADE: DANGER ({len(http_data['missing_headers'])} missing)")
        for header in http_data['missing_headers']:
            print(f"  ❌ Missing: {header}")
    else:
        print("GRADE: EXCELLENT (All standard security headers found)")

    # --- SSL/TLS CHECK ---
    print("\n[ SSL/TLS CONFIGURATION ]")
    print("-" * 30)
    
    if ssl_data['error']:
        print(f"STATUS: FAILURE - {ssl_data['error']}")
    else:
        print(f"STATUS: {ssl_data['status']}")
        print(f"Issued To: {ssl_data['issued_to']}")
        print(f"Expiry Date: {ssl_data['expiry_date']}")
        print(f"Days Remaining: {ssl_data['days_remaining']}")
        print(f"TLS Version: {ssl_data['tls_version']}")
    
    print("="*80)

def main():
    """Main function to load targets and run the scanner."""
    targets_file = 'targets.txt'
    
    if not os.path.exists(targets_file):
        print(f"Error: Required file '{targets_file}' not found. Please create it and list URLs.")
        return

    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not targets:
        print(f"Warning: '{targets_file}' is empty. Add URLs to scan.")
        return

    print(f"Starting passive scan of {len(targets)} targets...")
    for target_url in targets:
        if not target_url.startswith('http'):
             # Attempt to default to HTTPS if not specified, which is common for secure domains
             target_url = f"https://{target_url}" 

        print(f"\nScanning: {target_url}...")
        
        # 1. Run HTTP and Content Checks
        http_data = check_http_details(target_url)
        
        # 2. Run SSL/TLS Checks (only if the domain is secure/uses HTTPS)
        ssl_data = {}
        if target_url.lower().startswith('https'):
            ssl_data = check_ssl_details(target_url)
        else:
            ssl_data['error'] = 'Skipped SSL check for HTTP URL.'
            
        # 3. Generate Report Card
        generate_report_card(target_url, http_data, ssl_data)

if __name__ == '__main__':
    main()
