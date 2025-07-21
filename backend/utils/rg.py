import os
import requests
from urllib.parse import urlparse, urljoin, parse_qs
from fpdf import FPDF
import re
import ssl
import socket

def analyze_headers(url):
    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        issues = []
        # Security headers
        if 'X-Frame-Options' not in headers:
            issues.append('Missing X-Frame-Options header')
        if 'X-Content-Type-Options' not in headers:
            issues.append('Missing X-Content-Type-Options header')
        if 'Content-Security-Policy' not in headers:
            issues.append('Missing Content-Security-Policy header')
        if 'Strict-Transport-Security' not in headers:
            issues.append('Missing Strict-Transport-Security header')
        if 'Referrer-Policy' not in headers:
            issues.append('Missing Referrer-Policy header')
        if 'Permissions-Policy' not in headers:
            issues.append('Missing Permissions-Policy header')
        # HTTPS check
        if not url.startswith('https://'):
            issues.append('Site does not use HTTPS')
        # CORS misconfiguration
        if headers.get('Access-Control-Allow-Origin') == '*':
            issues.append('CORS misconfiguration: Access-Control-Allow-Origin is *')
        # Outdated server software
        server = headers.get('Server', '')
        if server:
            if any(x in server.lower() for x in ['apache/2.2', 'nginx/1.10', 'iis/6.0']):
                issues.append(f'Outdated server software: {server}')
        # Basic Auth
        if resp.status_code == 401 and 'WWW-Authenticate' in headers:
            issues.append('HTTP Basic Authentication enabled')
        # X-Powered-By/Server disclosure
        if 'X-Powered-By' in headers:
            issues.append(f'X-Powered-By header present: {headers["X-Powered-By"]}')
        if 'Server' in headers:
            issues.append(f'Server header present: {headers["Server"]}')
        # Cookie security flags
        cookies = resp.cookies
        for cookie in cookies:
            if not cookie.secure:
                issues.append(f'Cookie {cookie.name} missing Secure flag')
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append(f'Cookie {cookie.name} missing HttpOnly flag')
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append(f'Cookie {cookie.name} missing SameSite flag')
        return issues
    except Exception as e:
        return [f'Header check failed: {e}']

def check_open_redirect(url):
    try:
        test_url = url.rstrip('/') + '/?next=http://evil.com'
        resp = requests.get(test_url, allow_redirects=False, timeout=5)
        loc = resp.headers.get('Location', '')
        if 'evil.com' in loc:
            return ['Potential open redirect vulnerability']
        return []
    except Exception as e:
        return [f'Open redirect check failed: {e}']

def check_directory_listing(url):
    try:
        resp = requests.get(url, timeout=5)
        if 'Index of /' in resp.text:
            return ['Directory listing is enabled']
        return []
    except Exception as e:
        return [f'Directory listing check failed: {e}']

def check_sensitive_files(url):
    sensitive_paths = ['/.env', '/config.php', '/.git', '/backup.zip']
    issues = []
    for path in sensitive_paths:
        try:
            resp = requests.get(url.rstrip('/') + path, timeout=5)
            if resp.status_code == 200 and len(resp.content) > 0:
                issues.append(f'Sensitive file exposed: {path}')
        except Exception:
            continue
    return issues

def check_xss_reflection(url):
    try:
        test_param = 'xss_test'
        payload = '<script>alert(1)</script>'
        parsed = urlparse(url)
        base = url.split('?')[0]
        test_url = f"{base}?{test_param}={payload}"
        resp = requests.get(test_url, timeout=5)
        if payload in resp.text:
            return ['Potential XSS vulnerability (reflected)']
        return []
    except Exception as e:
        return [f'XSS check failed: {e}']

def check_csrf_token(url):
    try:
        resp = requests.get(url, timeout=5)
        if '<form' in resp.text:
            # Look for CSRF token in form
            if ('csrf' not in resp.text.lower()) and ('_token' not in resp.text.lower()):
                return ['No CSRF token found in forms']
        return []
    except Exception as e:
        return [f'CSRF check failed: {e}']

def check_admin_panel(url):
    admin_paths = ['/admin', '/admin/login', '/login', '/administrator']
    issues = []
    for path in admin_paths:
        try:
            resp = requests.get(url.rstrip('/') + path, timeout=5)
            if resp.status_code == 200 and ('login' in resp.text.lower() or 'admin' in resp.text.lower()):
                issues.append(f'Potential admin panel exposed: {path}')
        except Exception:
            continue
    return issues

def parse_sqlmap_log(content):
    if 'is vulnerable' in content or 'sqlmap identified the following injection point(s)' in content:
        return 'SQL Injection vulnerability found', 'high'
    elif 'all tested parameters do not appear to be injectable' in content:
        return 'No SQL Injection vulnerability found', 'low'
    else:
        return 'SQL Injection scan inconclusive', 'medium'

def calculate_risk_score(issues):
    if any('vulnerability found' in i or 'does not use HTTPS' in i or 'Sensitive file exposed' in i or 'Directory listing' in i or 'open redirect' in i or 'XSS' in i or 'No CSRF token' in i or 'admin panel' in i for i in issues):
        return 'high'
    elif issues:
        return 'medium'
    else:
        return 'low'

def generate_report(scan_id):
    log_path = f"logs/{scan_id}_sqlmap.txt"
    if not os.path.exists(log_path):
        raise FileNotFoundError
    with open(log_path, "r") as f:
        content = f.read()
    sql_summary, sql_risk = parse_sqlmap_log(content)
    url = 'https://' + scan_id.replace('_', '/').split('__')[0]
    header_issues = analyze_headers(url)
    ssl_issues = check_ssl_certificate(url)
    clickjacking_issues = check_clickjacking(url)
    open_redirect_issues = check_open_redirect_improved(url)
    dir_listing_issues = check_directory_listing(url)
    sensitive_file_issues = check_sensitive_files_improved(url)
    xss_issues = check_xss_reflection_improved(url)
    csrf_issues = check_csrf_token(url)
    admin_panel_issues = check_admin_panel(url)
    http_methods_issues = check_http_methods(url)
    robots_issues = check_robots_and_security_txt(url)
    api_issues = check_api_endpoints(url)
    csp_issues = check_csp_policy_strength(url)
    email_issues = check_email_disclosure(url)
    backup_issues = check_backup_files(url)
    git_svn_issues = check_exposed_git_svn(url)
    js_lib_issues = check_outdated_js_libs(url)
    issues = [sql_summary] + header_issues + ssl_issues + clickjacking_issues + open_redirect_issues + dir_listing_issues + sensitive_file_issues + xss_issues + csrf_issues + admin_panel_issues + http_methods_issues + robots_issues + api_issues + csp_issues + email_issues + backup_issues + git_svn_issues + js_lib_issues
    risk = calculate_risk_score(issues)
    return {
        "scan_id": scan_id,
        "risk_level": risk,
        "summary": f"Risk Level: {risk.upper()}\n" + '\n'.join(issues),
        "log": content,
        "url": url
    }

def get_recommendation_for_issue(issue):
    if 'SQL Injection' in issue:
        return 'Sanitize and parameterize all database queries.'
    if 'Missing X-Frame-Options' in issue:
        return 'Add X-Frame-Options header to prevent clickjacking.'
    if 'Missing X-Content-Type-Options' in issue:
        return 'Add X-Content-Type-Options header to prevent MIME sniffing.'
    if 'Missing Content-Security-Policy' in issue:
        return 'Add a Content-Security-Policy header.'
    if 'Missing Strict-Transport-Security' in issue:
        return 'Add Strict-Transport-Security header for HTTPS.'
    if 'Missing Referrer-Policy' in issue:
        return 'Add Referrer-Policy header.'
    if 'Missing Permissions-Policy' in issue:
        return 'Add Permissions-Policy header.'
    if 'does not use HTTPS' in issue:
        return 'Serve your site over HTTPS only.'
    if 'CORS misconfiguration' in issue:
        return 'Restrict Access-Control-Allow-Origin to trusted domains.'
    if 'Outdated server software' in issue:
        return 'Update your server software to the latest version.'
    if 'HTTP Basic Authentication enabled' in issue:
        return 'Avoid using HTTP Basic Authentication.'
    if 'X-Powered-By header present' in issue or 'Server header present' in issue:
        return 'Remove or obfuscate X-Powered-By/Server headers.'
    if 'Cookie' in issue and 'Secure flag' in issue:
        return 'Set Secure flag on all cookies.'
    if 'Cookie' in issue and 'HttpOnly' in issue:
        return 'Set HttpOnly flag on all cookies.'
    if 'Cookie' in issue and 'SameSite' in issue:
        return 'Set SameSite flag on all cookies.'
    if 'open redirect' in issue:
        return 'Validate and sanitize all redirect URLs.'
    if 'Directory listing' in issue:
        return 'Disable directory listing on your web server.'
    if 'Sensitive file exposed' in issue:
        return 'Remove sensitive files from the web root.'
    if 'XSS' in issue:
        return 'Sanitize user input and use proper output encoding.'
    if 'No CSRF token' in issue:
        return 'Implement CSRF protection for all forms.'
    if 'admin panel' in issue:
        return 'Restrict access to admin panels and use strong authentication.'
    return 'Review this issue and apply best security practices.'

def generate_pdf_report(scan_id, report_data):
    pdf_path = f"logs/{scan_id}_report.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    # Title
    pdf.set_font('Arial', 'B', 20)
    pdf.set_text_color(26, 34, 56)
    pdf.cell(0, 15, 'Xerago SecureScan Report', ln=True, align='C')
    pdf.ln(5)
    # Target URL
    pdf.set_font('Arial', '', 12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, f"Target URL: {report_data.get('url', scan_id)}", ln=True)
    # Risk Level
    risk = report_data.get('risk_level', 'unknown').lower()
    color = (0, 128, 0) if risk == 'low' else (255, 165, 0) if risk == 'medium' else (220, 53, 69)
    pdf.set_font('Arial', 'B', 14)
    pdf.set_text_color(*color)
    pdf.cell(0, 12, f"Risk Level: {risk.upper()}", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)
    # Summary
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Summary:', ln=True)
    pdf.set_font('Arial', '', 11)
    summary = report_data.get('summary', '')
    for line in summary.split('\n'):
        pdf.multi_cell(0, 8, line)
    pdf.ln(2)
    # Findings and Recommendations
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Findings & Recommendations:', ln=True)
    pdf.set_font('Arial', '', 11)
    issues = summary.split('\n')[1:]  # skip risk level line
    for issue in issues:
        if not issue.strip():
            continue
        pdf.set_text_color(26, 34, 56)
        pdf.multi_cell(0, 8, f"- {issue}")
        pdf.set_text_color(255, 106, 61)
        rec = get_recommendation_for_issue(issue)
        pdf.multi_cell(0, 8, f"  Recommendation: {rec}")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
    pdf.ln(2)
    # Footer
    pdf.set_y(-30)
    pdf.set_font('Arial', 'I', 10)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 10, f"Generated by Xerago SecureScan | {scan_id}", 0, 0, 'C')
    pdf.output(pdf_path)
    return pdf_path

def check_ssl_certificate(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = 443
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, port))
            cert = s.getpeercert()
            # Check expiry
            import datetime
            not_after = cert['notAfter']
            expire_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            if expire_date < datetime.datetime.utcnow():
                return ['SSL/TLS certificate is expired']
            return []
    except Exception as e:
        return [f'SSL/TLS certificate check failed: {e}']

def check_clickjacking(url):
    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        issues = []
        if 'X-Frame-Options' not in headers:
            issues.append('Missing X-Frame-Options header (clickjacking risk)')
        csp = headers.get('Content-Security-Policy', '')
        if 'frame-ancestors' not in csp:
            issues.append('CSP missing frame-ancestors directive (clickjacking risk)')
        return issues
    except Exception as e:
        return [f'Clickjacking check failed: {e}']

def check_http_methods(url):
    try:
        resp = requests.options(url, timeout=5)
        allowed = resp.headers.get('Allow', '')
        dangerous = [m for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT'] if m in allowed]
        if dangerous:
            return [f'Dangerous HTTP methods enabled: {", ".join(dangerous)}']
        return []
    except Exception as e:
        return [f'HTTP methods check failed: {e}']

def check_robots_and_security_txt(url):
    issues = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    try:
        robots = requests.get(urljoin(base, '/robots.txt'), timeout=5)
        if robots.status_code == 200 and 'Disallow:' not in robots.text:
            issues.append('robots.txt present but no Disallow rules')
    except Exception:
        pass
    try:
        sec = requests.get(urljoin(base, '/.well-known/security.txt'), timeout=5)
        if sec.status_code != 200:
            issues.append('security.txt missing')
    except Exception:
        issues.append('security.txt missing')
    return issues

def check_api_endpoints(url):
    api_paths = ['/api', '/graphql', '/v1/api', '/v2/api']
    issues = []
    for path in api_paths:
        try:
            resp = requests.get(url.rstrip('/') + path, timeout=5)
            if resp.status_code == 200 and ('api' in resp.text.lower() or 'graphql' in resp.text.lower()):
                issues.append(f'Potentially exposed API endpoint: {path}')
        except Exception:
            continue
    return issues

def check_csp_policy_strength(url):
    try:
        resp = requests.get(url, timeout=5)
        csp = resp.headers.get('Content-Security-Policy', '')
        if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
            return ['CSP policy is weak (unsafe-inline or unsafe-eval present)']
        return []
    except Exception as e:
        return [f'CSP policy check failed: {e}']

def check_email_disclosure(url):
    try:
        resp = requests.get(url, timeout=5)
        emails = re.findall(r'[\w\.-]+@[\w\.-]+', resp.text)
        if emails:
            return [f'Email addresses disclosed: {", ".join(set(emails))}']
        return []
    except Exception as e:
        return [f'Email disclosure check failed: {e}']

def check_backup_files(url):
    backup_paths = ['/index.php.bak', '/backup.tar.gz', '/db.sql', '/site.old', '/website.zip']
    issues = []
    for path in backup_paths:
        try:
            resp = requests.get(url.rstrip('/') + path, timeout=5)
            if resp.status_code == 200 and len(resp.content) > 0:
                issues.append(f'Backup file exposed: {path}')
        except Exception:
            continue
    return issues

def check_exposed_git_svn(url):
    issues = []
    for path in ['/.git/', '/.svn/']:
        try:
            resp = requests.get(url.rstrip('/') + path, timeout=5)
            if resp.status_code == 200:
                issues.append(f'Version control folder exposed: {path}')
        except Exception:
            continue
    return issues

def check_outdated_js_libs(url):
    try:
        resp = requests.get(url, timeout=5)
        libs = re.findall(r'<script[^>]+src=["\"](.*?)["\"][^>]*>', resp.text)
        issues = []
        for lib in libs:
            if any(x in lib for x in ['jquery-1', 'angular-1', 'bootstrap-3', 'vue-1', 'react-15']):
                issues.append(f'Potentially outdated JS library: {lib}')
        return issues
    except Exception as e:
        return [f'JS library check failed: {e}']

def check_xss_reflection_improved(url):
    try:
        payloads = ['<script>alert(1)</script>', '"onmouseover=alert(1)//', '<img src=x onerror=alert(1)>']
        params = ['q', 'search', 's', 'id', 'ref', 'page', 'input', 'query']
        parsed = urlparse(url)
        base = url.split('?')[0]
        found = []
        for param in params:
            for payload in payloads:
                test_url = f"{base}?{param}={payload}"
                resp = requests.get(test_url, timeout=5)
                if payload in resp.text:
                    found.append(f'Potential XSS vulnerability (reflected, param: {param})')
        return found
    except Exception as e:
        return [f'XSS check failed: {e}']

def check_open_redirect_improved(url):
    try:
        params = ['next', 'url', 'redirect', 'redir', 'dest', 'destination', 'goto']
        issues = []
        for param in params:
            test_url = url.rstrip('/') + f'/?{param}=http://evil.com'
            resp = requests.get(test_url, allow_redirects=False, timeout=5)
            loc = resp.headers.get('Location', '')
            if 'evil.com' in loc:
                issues.append(f'Potential open redirect vulnerability (param: {param})')
        return issues
    except Exception as e:
        return [f'Open redirect check failed: {e}']

def check_sensitive_files_improved(url):
    sensitive_paths = ['/.env', '/config.php', '/.git', '/backup.zip', '/.htpasswd', '/web.config', '/wp-config.php', '/.DS_Store', '/.bash_history', '/id_rsa', '/.ssh/authorized_keys']
    issues = []
    for path in sensitive_paths:
        try:
            resp = requests.get(url.rstrip('/') + path, timeout=5)
            if resp.status_code == 200 and len(resp.content) > 0:
                issues.append(f'Sensitive file exposed: {path}')
        except Exception:
            continue
    return issues 