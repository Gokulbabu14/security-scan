import React, { useState } from 'react';
import axios from 'axios';
import xeragoLogo from './xerago-logo.png';

const ALL_ATTACK_TYPES = [
  { key: 'sql_injection', label: 'SQL Injection' },
  { key: 'xss', label: 'XSS' },
  { key: 'ssl', label: 'SSL/TLS' },
  { key: 'headers', label: 'Headers' },
  { key: 'clickjacking', label: 'Clickjacking' },
  { key: 'open_redirect', label: 'Open Redirect' },
  { key: 'sensitive_files', label: 'Sensitive Files' },
  { key: 'directory_listing', label: 'Directory Listing' },
  { key: 'csrf', label: 'CSRF' },
  { key: 'admin_panel', label: 'Admin Panel' },
  { key: 'http_methods', label: 'HTTP Methods' },
  { key: 'robots_security_txt', label: 'robots.txt / security.txt' },
  { key: 'api_endpoints', label: 'API Endpoints' },
  { key: 'csp_policy', label: 'CSP Policy' },
  { key: 'email_disclosure', label: 'Email Disclosure' },
  { key: 'backup_files', label: 'Backup Files' },
  { key: 'version_control', label: 'Version Control' },
  { key: 'js_libraries', label: 'JS Libraries' },
];

// Helper to group findings by category
function groupFindings(issues) {
  const groups = {
    'SSL/TLS': [],
    'Headers': [],
    'Clickjacking': [],
    'Open Redirect': [],
    'Directory Listing': [],
    'Sensitive Files': [],
    'XSS': [],
    'CSRF': [],
    'Admin Panel': [],
    'HTTP Methods': [],
    'robots.txt / security.txt': [],
    'API Endpoints': [],
    'CSP Policy': [],
    'Email Disclosure': [],
    'Backup Files': [],
    'Version Control': [],
    'JS Libraries': [],
    'SQL Injection': [],
    'Other': [],
  };
  issues.forEach(issue => {
    const i = issue.toLowerCase();
    if (i.includes('ssl') || i.includes('tls') || i.includes('certificate')) groups['SSL/TLS'].push(issue);
    else if (i.includes('header')) groups['Headers'].push(issue);
    else if (i.includes('clickjacking')) groups['Clickjacking'].push(issue);
    else if (i.includes('open redirect')) groups['Open Redirect'].push(issue);
    else if (i.includes('directory listing')) groups['Directory Listing'].push(issue);
    else if (i.includes('sensitive file')) groups['Sensitive Files'].push(issue);
    else if (i.includes('xss')) groups['XSS'].push(issue);
    else if (i.includes('csrf')) groups['CSRF'].push(issue);
    else if (i.includes('admin panel')) groups['Admin Panel'].push(issue);
    else if (i.includes('http methods')) groups['HTTP Methods'].push(issue);
    else if (i.includes('robots.txt') || i.includes('security.txt')) groups['robots.txt / security.txt'].push(issue);
    else if (i.includes('api endpoint') || i.includes('graphql')) groups['API Endpoints'].push(issue);
    else if (i.includes('csp')) groups['CSP Policy'].push(issue);
    else if (i.includes('email')) groups['Email Disclosure'].push(issue);
    else if (i.includes('backup file')) groups['Backup Files'].push(issue);
    else if (i.includes('version control')) groups['Version Control'].push(issue);
    else if (i.includes('js library')) groups['JS Libraries'].push(issue);
    else if (i.includes('sql injection')) groups['SQL Injection'].push(issue);
    else groups['Other'].push(issue);
  });
  return groups;
}

// Helper to get a recommendation for a finding (should match backend logic)
function getRecommendation(issue) {
  if (issue.includes('SQL Injection')) return 'Sanitize and parameterize all database queries.';
  if (issue.includes('X-Frame-Options')) return 'Add X-Frame-Options header to prevent clickjacking.';
  if (issue.includes('X-Content-Type-Options')) return 'Add X-Content-Type-Options header to prevent MIME sniffing.';
  if (issue.includes('Content-Security-Policy')) return 'Add a Content-Security-Policy header.';
  if (issue.includes('Strict-Transport-Security')) return 'Add Strict-Transport-Security header for HTTPS.';
  if (issue.includes('Referrer-Policy')) return 'Add Referrer-Policy header.';
  if (issue.includes('Permissions-Policy')) return 'Add Permissions-Policy header.';
  if (issue.includes('HTTPS')) return 'Serve your site over HTTPS only.';
  if (issue.includes('CORS')) return 'Restrict Access-Control-Allow-Origin to trusted domains.';
  if (issue.includes('Outdated server software')) return 'Update your server software to the latest version.';
  if (issue.includes('HTTP Basic Authentication')) return 'Avoid using HTTP Basic Authentication.';
  if (issue.includes('X-Powered-By') || issue.includes('Server header')) return 'Remove or obfuscate X-Powered-By/Server headers.';
  if (issue.includes('Cookie') && issue.includes('Secure flag')) return 'Set Secure flag on all cookies.';
  if (issue.includes('Cookie') && issue.includes('HttpOnly')) return 'Set HttpOnly flag on all cookies.';
  if (issue.includes('Cookie') && issue.includes('SameSite')) return 'Set SameSite flag on all cookies.';
  if (issue.includes('open redirect')) return 'Validate and sanitize all redirect URLs.';
  if (issue.includes('Directory listing')) return 'Disable directory listing on your web server.';
  if (issue.includes('Sensitive file')) return 'Remove sensitive files from the web root.';
  if (issue.includes('XSS')) return 'Sanitize user input and use proper output encoding.';
  if (issue.includes('CSRF')) return 'Implement CSRF protection for all forms.';
  if (issue.includes('admin panel')) return 'Restrict access to admin panels and use strong authentication.';
  if (issue.includes('SSL') || issue.includes('TLS')) return 'Ensure your SSL/TLS certificate is valid and not expired.';
  if (issue.includes('clickjacking')) return 'Add X-Frame-Options or frame-ancestors CSP directive.';
  if (issue.includes('HTTP methods')) return 'Disable dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT).';
  if (issue.includes('robots.txt')) return 'Add Disallow rules to robots.txt as needed.';
  if (issue.includes('security.txt')) return 'Add a security.txt file for vulnerability disclosure.';
  if (issue.includes('API endpoint')) return 'Restrict access to API endpoints and use authentication.';
  if (issue.includes('CSP policy')) return 'Strengthen your Content-Security-Policy.';
  if (issue.includes('Email addresses')) return 'Avoid disclosing email addresses in public HTML.';
  if (issue.includes('Backup file')) return 'Remove backup files from the web root.';
  if (issue.includes('Version control')) return 'Do not expose .git or .svn folders.';
  if (issue.includes('JS library')) return 'Update JavaScript libraries to the latest version.';
  return 'Review this issue and apply best security practices.';
}

function RiskBadge({ risk }) {
  let color = '#28a745';
  if (risk === 'medium') color = '#ffc107';
  if (risk === 'high') color = '#dc3545';
  return (
    <span style={{
      display: 'inline-block',
      background: color,
      color: '#fff',
      borderRadius: 8,
      fontWeight: 700,
      fontSize: 15,
      padding: '4px 14px',
      marginLeft: 12,
      letterSpacing: 0.5,
      verticalAlign: 'middle',
    }}>{risk && risk.toUpperCase()}</span>
  );
}

function App() {
  const [targetUrl, setTargetUrl] = useState('');
  const [attackTypes, setAttackTypes] = useState(ALL_ATTACK_TYPES.map(a => a.key));
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const apiBase = 'http://localhost:8000';

  const handleScan = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${apiBase}/analyze`, {
        target_url: targetUrl,
        attack_types: attackTypes,
      });
      const scanId = res.data.scan_id;
      setTimeout(async () => {
        try {
          const reportRes = await axios.get(`${apiBase}/report/${scanId}`);
          setReport(reportRes.data);
        } catch (err) {
          setReport({ log: 'Report not found or error occurred.' });
        }
        setLoading(false);
      }, 8000);
    } catch (err) {
      setReport({ log: 'Scan failed or API error.' });
      setLoading(false);
    }
  };

  const toggleAttackType = (type) => {
    setAttackTypes((prev) =>
      prev.includes(type)
        ? prev.filter((t) => t !== type)
        : [...prev, type]
    );
  };

  // Xerago.com style header with logo
  const headerBar = (
    <header style={{
      width: '100%',
      background: '#fff',
      boxShadow: '0 2px 12px 0 rgba(26, 34, 56, 0.04)',
      padding: 0,
      marginBottom: 48,
      borderBottom: '1.5px solid #f2f2f2',
    }}>
      <div style={{
        maxWidth: 1200,
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        height: 72,
        padding: '0 32px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
          <img src={xeragoLogo} alt="Xerago Logo" style={{ height: 44, width: 'auto', display: 'block' }} />
          <span style={{
            fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
            fontWeight: 500,
            fontSize: 20,
            color: '#222',
            letterSpacing: 0.2,
            marginLeft: 8,
            opacity: 0.85,
            borderLeft: '1.5px solid #bbb',
            paddingLeft: 16,
          }}>
            The Science of Digital
          </span>
        </div>
      </div>
    </header>
  );

  // Always show all attack type options
  const attackTypeSelector = (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 28, marginTop: 8 }}>
      {ALL_ATTACK_TYPES.map(({ key, label }) => (
        <button
          key={key}
          onClick={() => toggleAttackType(key)}
          style={{
            padding: '8px 18px',
            borderRadius: 999,
            border: 'none',
            fontWeight: 700,
            fontSize: 14,
            background: attackTypes.includes(key)
              ? 'linear-gradient(90deg, #ff6a3d 0%, #ff9a3d 100%)'
              : '#e6eaf1',
            color: attackTypes.includes(key) ? '#fff' : '#1a2238',
            boxShadow: attackTypes.includes(key)
              ? '0 2px 8px 0 rgba(255, 106, 61, 0.10)'
              : '0 1px 4px 0 rgba(26, 34, 56, 0.04)',
            cursor: 'pointer',
            borderBottom: attackTypes.includes(key)
              ? '2px solid #ff6a3d'
              : '2px solid transparent',
            transition: 'all 0.2s',
            fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
            marginBottom: 4,
          }}
          type="button"
        >
          {label}
        </button>
      ))}
    </div>
  );

  // Xerago.com style report card (grouped findings, risk badge, recommendations)
  const renderReport = () => {
    if (!report) return null;
    const scanId = report.scan_id;
    const risk = report.risk_level;
    let summary = report.summary || '';
    let issues = summary.split('\n').slice(1).filter(Boolean); // skip risk level line
    const groups = groupFindings(issues);
    // Always show the download button, disable if scanId is missing
    const pdfUrl = scanId ? `${apiBase}/report/${scanId}/pdf` : null;
    return (
      <div style={reportCardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 18 }}>
          <span style={{ fontWeight: 700, fontSize: 20, color: '#1a2238', letterSpacing: 0.5 }}>Website Risk Level</span>
          <RiskBadge risk={risk} />
        </div>
        {Object.entries(groups).map(([cat, findings]) => (
          findings.length > 0 && (
            <div key={cat} style={{ marginBottom: 18 }}>
              <div style={{ fontWeight: 700, color: '#ff6a3d', fontSize: 17, marginBottom: 6 }}>{cat}</div>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {findings.map((issue, idx) => (
                  <li key={idx} style={{ marginBottom: 4, color: '#1a2238', fontSize: 15 }}>
                    {issue}
                    <div style={{ color: '#888', fontSize: 13, marginTop: 2, marginBottom: 6 }}>
                      <span style={{ color: '#ff6a3d', fontWeight: 600 }}>Recommendation:</span> {getRecommendation(issue)}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )
        ))}
        <div style={{ textAlign: 'center', marginTop: 32 }}>
          <a
            href={pdfUrl || '#'}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: 'inline-block',
              marginTop: 0,
              padding: '14px 32px',
              background: pdfUrl ? 'linear-gradient(90deg, #ff6a3d 0%, #ff9a3d 100%)' : '#ccc',
              color: '#fff',
              borderRadius: 14,
              fontWeight: 800,
              fontSize: 17,
              textDecoration: 'none',
              boxShadow: pdfUrl ? '0 4px 16px 0 rgba(255, 106, 61, 0.10)' : 'none',
              letterSpacing: 0.5,
              fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
              transition: 'background 0.2s, box-shadow 0.2s',
              pointerEvents: pdfUrl ? 'auto' : 'none',
              opacity: pdfUrl ? 1 : 0.5,
            }}
            download
          >
            Download PDF Report
          </a>
        </div>
      </div>
    );
  };

  const reportCardStyle = {
    marginTop: 40,
    padding: 32,
    background: '#fff',
    borderRadius: 20,
    boxShadow: '0 4px 32px 0 rgba(26, 34, 56, 0.10)',
    border: '1.5px solid #f2f2f2',
    fontSize: 16,
    color: '#333',
    wordBreak: 'break-word',
    whiteSpace: 'pre-wrap',
    fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
  };
  const reportLogStyle = {
    fontFamily: 'SFMono-Regular, Menlo, Monaco, Consolas, monospace',
    fontSize: 16,
    margin: 0,
    color: '#ff6a3d',
    background: 'none',
    padding: 0,
    border: 'none',
    whiteSpace: 'pre-wrap',
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #f5f6fa 0%, #e6eaf1 100%)',
      fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
      padding: 0,
      margin: 0,
    }}>
      {headerBar}
      <main style={{
        maxWidth: 520,
        margin: '0 auto',
        padding: '40px 24px',
        borderRadius: 28,
        background: '#fff',
        boxShadow: '0 8px 32px 0 rgba(26, 34, 56, 0.10)',
        border: '1.5px solid #f2f2f2',
        marginTop: 24,
        marginBottom: 48,
      }}>
        <h1 style={{
          fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
          fontWeight: 700,
          fontSize: 28,
          color: '#1a2238',
          marginBottom: 32,
          letterSpacing: 0.5,
        }}>
          Website Security Analyzer
        </h1>
        <input
          type="text"
          placeholder="Enter website URL (https://example.com)"
          style={{
            width: '100%',
            padding: '18px 20px',
            borderRadius: 14,
            border: '1.5px solid #bfc8e6',
            fontSize: 17,
            marginBottom: 22,
            background: '#f5f6fa',
            boxShadow: '0 1px 4px 0 rgba(26, 34, 56, 0.04)',
            outline: 'none',
            transition: 'border 0.2s',
            fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
          }}
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
        />
        {attackTypeSelector}
        <button
          onClick={handleScan}
          style={{
            width: '100%',
            background: 'linear-gradient(90deg, #ff6a3d 0%, #ff9a3d 100%)',
            color: '#fff',
            padding: '18px 0',
            border: 'none',
            borderRadius: 14,
            fontWeight: 800,
            fontSize: 18,
            boxShadow: '0 4px 16px 0 rgba(255, 106, 61, 0.10)',
            marginBottom: 18,
            cursor: loading ? 'not-allowed' : 'pointer',
            opacity: loading ? 0.7 : 1,
            transition: 'opacity 0.2s',
            fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
            letterSpacing: 0.5,
          }}
          disabled={loading}
        >
          {loading ? "Scanning..." : "Start Vulnerability Scan"}
        </button>
        {renderReport()}
      </main>
      <footer style={{
        textAlign: 'center',
        marginTop: 0,
        marginBottom: 24,
        opacity: 0.8,
        fontSize: 15,
        letterSpacing: 0.2,
        color: '#1a2238',
        fontWeight: 600,
        fontFamily: 'Poppins, Montserrat, Arial, sans-serif',
      }}>
        Xerago SecureScan &copy; {new Date().getFullYear()}
      </footer>
    </div>
  );
}

export default App; 