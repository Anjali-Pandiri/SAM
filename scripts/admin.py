#!/usr/bin/env python3
"""
admin.py  —  SysAdmin Automation Script
========================================
This script demonstrates what a SysAdmin does programmatically:
- Connects to the running application via its REST API
- Generates API tokens for authentication
- Runs health checks and vulnerability scans
- Applies patches with audit logging
- Generates a management report

INTERVIEW TALKING POINT:
"This script represents the 'Scripting/Automation' skill from the job description.
Instead of doing every admin task manually through a web UI, I wrote a Python script
that automates routine SysAdmin operations — health monitoring, patch management,
security scanning. This is exactly how enterprise IT teams work at scale."

HOW TO RUN:
    # First, start the Docker containers:
    docker-compose up -d
    
    # Then run this script:
    python scripts/admin.py
    
    # Or run specific sections:
    python scripts/admin.py --section health
    python scripts/admin.py --section scan
    python scripts/admin.py --section report
"""

# ── IMPORTS ────────────────────────────────────────────────────────────────────
import requests     # Third-party: HTTP client library. Makes API calls easy.
import json         # Built-in: parse and format JSON data
import sys          # Built-in: system functions (exit, argv, stdout)
import argparse     # Built-in: parses command-line arguments like --section
import time         # Built-in: time functions (sleep, timestamps)
import datetime     # Built-in: date and time manipulation

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
BASE_URL  = "http://localhost:5000"
# The URL of our running Flask application.
# In a real enterprise: this would be something like https://monitor.cfa.harvard.edu

USERNAME  = "admin_demo"
# Username to associate with our API token


# ── COLORS FOR TERMINAL OUTPUT ─────────────────────────────────────────────────
# ANSI escape codes — special character sequences that terminals interpret as colors
# \033[ starts an escape sequence, numbers select color, m ends the sequence

class Colors:
    """ANSI color codes for pretty terminal output."""
    RESET  = '\033[0m'   # Reset to default
    BOLD   = '\033[1m'   # Bold text
    RED    = '\033[91m'  # Bright red    — errors, critical
    GREEN  = '\033[92m'  # Bright green  — success, healthy
    YELLOW = '\033[93m'  # Bright yellow — warnings
    BLUE   = '\033[94m'  # Bright blue   — info
    CYAN   = '\033[96m'  # Cyan          — section headers
    WHITE  = '\033[97m'  # Bright white  — labels

def color(text, code):
    """Wraps text with a color code and reset."""
    return f"{code}{text}{Colors.RESET}"

def header(title):
    """Prints a formatted section header."""
    print(f"\n{color('═' * 60, Colors.CYAN)}")
    print(f"{color(f'  {title}', Colors.BOLD + Colors.CYAN)}")
    print(f"{color('═' * 60, Colors.CYAN)}")


# ── STEP 1: GENERATE API TOKEN ─────────────────────────────────────────────────
def get_api_token():
    """
    POST /api/token to generate an authentication token.
    
    WHAT IS HAPPENING HERE?
    We make an HTTP POST request to our Flask API.
    The server generates a secure random token, stores its hash, and returns
    the raw token to us ONCE.
    We save this token for all subsequent authenticated requests.
    
    HOW requests.post() WORKS:
    requests.post(url, json=data)
    - url    = where to send the request
    - json=  = automatically serializes dict to JSON and sets Content-Type header
    Returns a Response object with:
    - .status_code = HTTP status (200, 201, 400, 401...)
    - .json()      = parses the response body as JSON
    - .text        = raw response body as string
    """
    
    header("STEP 1: API Authentication — Generating Token")
    print(f"  Requesting token from: {BASE_URL}/api/token")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/token",
            json={"username": USERNAME},
            timeout=10  
            # timeout=10: raise exception if no response within 10 seconds
            # ALWAYS set timeouts — hanging requests can freeze scripts
        )
        
        # Check if the request succeeded
        response.raise_for_status()
        # raise_for_status() raises an exception if status code is 4xx or 5xx
        # This is cleaner than manually checking response.status_code == 200
        
        data  = response.json()
        # .json() parses the JSON response body into a Python dict
        
        token = data['token']
        # Extract the actual token string from the response
        
        print(color(f"  ✓ Token generated for user: {data['username']}", Colors.GREEN))
        print(f"  Token preview: {token[:16]}...{token[-8:]}")
        print(f"  Expires: {data['expires']}")
        print(color("  ⚠ Token shown once — would be saved to secure vault in production", Colors.YELLOW))
        
        return token
        
    except requests.exceptions.ConnectionError:
        print(color("  ✗ Cannot connect to application. Is Docker running?", Colors.RED))
        print(f"  Try: docker-compose up -d")
        sys.exit(1)
        # sys.exit(1) exits the script with error code 1
        # Convention: 0 = success, non-zero = error
        
    except requests.exceptions.HTTPError as e:
        print(color(f"  ✗ HTTP error: {e}", Colors.RED))
        sys.exit(1)


# ── STEP 2: HEALTH CHECK ──────────────────────────────────────────────────────
def check_health():
    """
    GET /api/health — reads real-time system metrics.
    
    This demonstrates monitoring — a core SysAdmin responsibility.
    In enterprise: this would be called by Zabbix, Nagios, or Prometheus
    every 30 seconds to track system health over time.
    """
    
    header("STEP 2: System Health Check")
    
    response = requests.get(f"{BASE_URL}/api/health", timeout=10)
    data = response.json()
    
    # Color-code the status
    status_color = {
        'healthy':  Colors.GREEN,
        'warning':  Colors.YELLOW,
        'critical': Colors.RED
    }.get(data['status'], Colors.WHITE)
    # .get(key, default) — returns default if key not found
    # Equivalent to: if key in dict: return dict[key] else: return default
    
    print(f"\n  Overall Status: {color(data['status'].upper(), status_color)}")
    
    # System info
    sys_info = data['system']
    print(f"\n  {'System Information':}")
    print(f"    OS:       {sys_info['os']}")
    print(f"    Python:   {sys_info['python']}")
    print(f"    Host:     {sys_info['hostname']}")
    
    # CPU
    cpu = data['cpu']
    cpu_bar = _make_bar(cpu['percent'])
    cpu_col = Colors.RED if cpu['percent'] > 90 else Colors.YELLOW if cpu['percent'] > 75 else Colors.GREEN
    print(f"\n  CPU:    {cpu_bar} {color(f\"{cpu['percent']:.1f}%\", cpu_col)}")
    
    # Memory
    mem = data['memory']
    mem_bar = _make_bar(mem['percent'])
    mem_col = Colors.RED if mem['percent'] > 90 else Colors.YELLOW if mem['percent'] > 75 else Colors.GREEN
    print(f"  Memory: {mem_bar} {color(f\"{mem['percent']:.1f}%\", mem_col)} ({mem['used_gb']} / {mem['total_gb']} GB)")
    
    # Disk
    disk = data['disk']
    disk_bar = _make_bar(disk['percent'])
    disk_col = Colors.RED if disk['percent'] > 90 else Colors.YELLOW if disk['percent'] > 80 else Colors.GREEN
    print(f"  Disk:   {disk_bar} {color(f\"{disk['percent']:.1f}%\", disk_col)} ({disk['used_gb']} / {disk['total_gb']} GB)")
    
    return data


def _make_bar(percent, width=20):
    """
    Creates a visual progress bar string.
    
    Example: _make_bar(45, 20)  →  "[█████████░░░░░░░░░░░]"
    
    How it works:
    filled = int(45 * 20 / 100) = int(9.0) = 9
    bar = "█" * 9 + "░" * (20 - 9)
        = "█████████" + "░░░░░░░░░░░"
    """
    filled = int(percent * width / 100)
    # percent * width / 100 = how many "filled" blocks
    
    bar = "█" * filled + "░" * (width - filled)
    # String multiplication: "x" * 3 = "xxx"
    
    return f"[{bar}]"


# ── STEP 3: SOFTWARE INVENTORY ────────────────────────────────────────────────
def show_inventory():
    """GET /api/software — show all managed enterprise software."""
    
    header("STEP 3: Enterprise Software Inventory")
    
    response = requests.get(f"{BASE_URL}/api/software", timeout=10)
    data     = response.json()
    
    print(f"\n  Total software tracked: {color(str(data['count']), Colors.CYAN)}\n")
    
    # Print table header
    print(f"  {'ID':<4} {'Name':<22} {'Version':<10} {'Status':<10} {'Last Patch':<14}")
    print(f"  {'─'*4} {'─'*22} {'─'*10} {'─'*10} {'─'*14}")
    
    for sw in data['software']:
        # Color code by status
        status_color = Colors.GREEN if sw['status'] == 'active' else Colors.RED
        
        # Calculate days since last patch
        patch_info = sw['last_patch'] or 'Never'
        if sw['last_patch']:
            try:
                last = datetime.datetime.fromisoformat(sw['last_patch'].split('T')[0])
                days = (datetime.datetime.now() - last).days
                patch_info = f"{sw['last_patch'][:10]} ({days}d)"
                if days > 90:
                    patch_info = color(patch_info, Colors.RED)
            except:
                pass
        
        print(f"  {sw['id']:<4} {sw['name']:<22} {sw['version']:<10} "
              f"{color(sw['status'], status_color):<20} {patch_info}")
    
    return data


# ── STEP 4: VULNERABILITY SCAN ────────────────────────────────────────────────
def run_vulnerability_scan(token):
    """
    GET /api/security/scan — simulates a vulnerability assessment.
    
    Real enterprise equivalent:
    - Nessus (commercial vulnerability scanner)
    - OpenVAS (open source)
    - AWS Inspector (scans EC2 instances)
    - Qualys (SaaS scanner)
    
    They check software versions against CVE databases and flag:
    - End-of-life software
    - Unpatched vulnerabilities
    - Misconfigurations
    - Missing security controls
    """
    
    header("STEP 4: Vulnerability Scan — Security Assessment")
    
    headers = {'X-API-Key': token}
    # HTTP headers dictionary — sent with the request
    # Our API requires X-API-Key for protected endpoints
    
    print("  Running vulnerability assessment...")
    time.sleep(1)  # Simulate scan time (dramatic effect)
    
    response = requests.get(
        f"{BASE_URL}/api/security/scan",
        headers=headers,
        timeout=30
    )
    data = response.json()
    
    print(f"\n  Scan completed at: {data['scan_time'][:19]}")
    print(f"  Software scanned:  {data['total_software']}")
    
    if data['findings_count'] == 0:
        print(color("\n  ✓ No vulnerabilities found", Colors.GREEN))
        return data
    
    print(f"\n  {color('⚠ Findings:', Colors.YELLOW)} {data['findings_count']} software items with issues")
    
    # Severity summary
    summary = data.get('severity_summary', {})
    if summary:
        print(f"\n  Severity Breakdown:")
        severity_colors = {'CRITICAL': Colors.RED, 'HIGH': Colors.RED, 'MEDIUM': Colors.YELLOW, 'LOW': Colors.CYAN}
        for sev, count in sorted(summary.items()):
            col = severity_colors.get(sev, Colors.WHITE)
            print(f"    {color(f'{sev:10}', col)}: {count} issue(s)")
    
    # Detail each finding
    print(f"\n  Detailed Findings:")
    for finding in data['findings']:
        print(f"\n  📦 {color(finding['software'], Colors.BOLD)} v{finding['version']}")
        for issue in finding['issues']:
            sev_col = Colors.RED if issue['severity'] in ('CRITICAL', 'HIGH') else Colors.YELLOW
            print(f"     [{color(issue['severity'], sev_col)}] {issue['type']}")
            print(f"     → {issue.get('desc', issue.get('message', ''))}")
    
    return data


# ── STEP 5: APPLY A PATCH ─────────────────────────────────────────────────────
def apply_patch(token, software_id=1):
    """
    POST /api/software/{id}/patch — simulates patching enterprise software.
    
    WHAT IS PATCH MANAGEMENT?
    The process of identifying, acquiring, testing, and installing updates
    (patches) to software. Critical for:
    - Security: patches fix known vulnerabilities
    - Stability: patches fix bugs
    - Compliance: many standards (NIST, PCI-DSS) require current patches
    
    CHANGE MANAGEMENT (ITIL):
    Every patch should go through Change Management:
    1. Change Request (CR) — document what will change
    2. Approval — review and approve the change
    3. Implementation — apply the change
    4. Verification — confirm it worked
    5. Post-Implementation Review — did anything break?
    
    Our audit log simulates this paper trail.
    """
    
    header("STEP 5: Patch Management — Apply Security Update")
    
    print(f"  Patching software ID: {software_id}")
    print(f"  Simulating: CVE-2025-0001 remediation for Oracle ERP")
    
    headers = {'X-API-Key': token, 'X-Username': USERNAME}
    payload = {
        'version': '19c.1-patched',
        'notes':   'CVE-2025-0001 remediation — SQL injection in HR module. Change ticket: CHG-2026-001'
    }
    
    response = requests.post(
        f"{BASE_URL}/api/software/{software_id}/patch",
        json=payload,
        headers=headers,
        timeout=10
    )
    
    if response.status_code == 200:
        data = response.json()
        print(color(f"\n  ✓ Patch applied successfully", Colors.GREEN))
        print(f"    Software:    {data['name']}")
        print(f"    New version: {data['new_version']}")
        print(f"    Patched at:  {data['patched_at'][:19]} UTC")
        print(f"    Audit trail: CREATED (viewable in /api/audit)")
    else:
        print(color(f"\n  ✗ Patch failed: {response.json().get('error')}", Colors.RED))
    
    return response.json()


# ── STEP 6: VIEW AUDIT LOG ────────────────────────────────────────────────────
def show_audit_log(token):
    """
    GET /api/audit — display the administrative audit trail.
    
    ITIL Change Management requires that every significant action be logged.
    This is also required by:
    - NIST SP 800-53 (AU family controls — Audit and Accountability)
    - SOC 2 (security auditing)
    - FISMA (federal information security)
    
    The audit log proves:
    - Who did what and when
    - What changed and why
    - Compliance with change management procedures
    """
    
    header("STEP 6: Audit Log — ITIL Change Management Trail")
    
    headers = {'X-API-Key': token}
    response = requests.get(
        f"{BASE_URL}/api/audit?limit=10",
        headers=headers,
        timeout=10
    )
    data = response.json()
    
    print(f"\n  Last {len(data['audit_log'])} administrative actions:\n")
    
    action_colors = {
        'PATCH_APPLIED':      Colors.GREEN,
        'TOKEN_CREATED':      Colors.BLUE,
        'VULNERABILITY_SCAN': Colors.YELLOW,
    }
    
    for log in data['audit_log']:
        timestamp = log['timestamp'][:19] if log['timestamp'] else 'Unknown'
        action    = log['action']
        col       = action_colors.get(action, Colors.WHITE)
        
        print(f"  {timestamp} UTC | {color(f'{action:22}', col)} | {log.get('user', 'system')}")
        if log.get('details'):
            print(f"  {'':>19}   → {log['details'][:70]}")


# ── STEP 7: GENERATE REPORT ───────────────────────────────────────────────────
def generate_report(health_data, inventory_data, scan_data):
    """
    Generates a management summary report.
    
    In enterprise IT, SysAdmins regularly produce:
    - System health reports for management
    - Security assessment summaries
    - Patch compliance reports
    - Capacity planning reports
    
    This would typically be emailed to IT leadership or fed into a ITSM tool
    like ServiceNow, JIRA Service Management, or BMC Remedy.
    """
    
    header("STEP 7: Management Report — System Summary")
    
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    
    report_lines = [
        f"",
        f"  {'CfA Software Administration — Health Report':}",
        f"  Generated: {now}",
        f"  {'─' * 50}",
        f"",
        f"  SYSTEM HEALTH",
        f"  Status:      {health_data.get('status', 'unknown').upper()}",
        f"  CPU Usage:   {health_data.get('cpu', {}).get('percent', 0):.1f}%",
        f"  Memory:      {health_data.get('memory', {}).get('percent', 0):.1f}%",
        f"  Disk:        {health_data.get('disk', {}).get('percent', 0):.1f}%",
        f"",
        f"  SOFTWARE INVENTORY",
        f"  Total Apps:  {inventory_data.get('count', 0)}",
        f"  Active:      {sum(1 for s in inventory_data.get('software', []) if s['status'] == 'active')}",
        f"  Legacy:      {sum(1 for s in inventory_data.get('software', []) if s['status'] == 'legacy')}",
        f"",
        f"  SECURITY FINDINGS",
        f"  Items w/ Issues: {scan_data.get('findings_count', 0)}",
    ]
    
    summary = scan_data.get('severity_summary', {})
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sev in summary:
            report_lines.append(f"  {sev}: {summary[sev]}")
    
    report_lines += [
        f"",
        f"  RECOMMENDATIONS",
        f"  1. Immediately decommission or isolate Legacy FITS System",
        f"  2. Apply Oracle ERP patch for CVE-2025-0001 (CRITICAL)",
        f"  3. Review all software with patches > 90 days",
        f"  4. Schedule quarterly vulnerability scan review",
        f"",
        f"  {'─' * 50}",
        f"  Report generated by CfA Software Health Monitor v1.0",
    ]
    
    for line in report_lines:
        print(color(line, Colors.WHITE))
    
    # Save report to file
    report_path = f"data/logs/report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        import os
        os.makedirs('data/logs', exist_ok=True)
        with open(report_path, 'w') as f:
            # Strip color codes when writing to file
            clean_lines = [l.replace(Colors.WHITE, '').replace(Colors.RESET, '') for l in report_lines]
            f.write('\n'.join(clean_lines))
        print(color(f"\n  Report saved to: {report_path}", Colors.GREEN))
    except Exception as e:
        print(color(f"\n  Could not save report: {e}", Colors.YELLOW))


# ── MAIN ENTRYPOINT ───────────────────────────────────────────────────────────
def main():
    """
    Orchestrates the full SysAdmin workflow.
    
    argparse lets users run: python admin.py --section health
    """
    
    parser = argparse.ArgumentParser(
        description='CfA SysAdmin Automation Demo',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/admin.py              # Run full demo
  python scripts/admin.py --section health
  python scripts/admin.py --section scan
  python scripts/admin.py --section report
        """
    )
    parser.add_argument(
        '--section',
        choices=['all', 'health', 'inventory', 'scan', 'patch', 'audit', 'report'],
        default='all',
        help='Which section to run (default: all)'
    )
    args = parser.parse_args()
    # args.section will be whatever the user passed, e.g., "health"
    
    print(color("\n  CfA Software Health Monitor — Admin Demo", Colors.BOLD + Colors.CYAN))
    print(color("  Smithsonian Astrophysical Observatory", Colors.CYAN))
    print(color("  IT Specialist Portfolio Project", Colors.CYAN))
    
    section = args.section
    
    # Always get a token first (needed for protected endpoints)
    token = get_api_token()
    
    # Run selected sections
    health_data    = check_health()    if section in ('all', 'health', 'report')     else {}
    inventory_data = show_inventory()  if section in ('all', 'inventory', 'report')  else {'count': 0, 'software': []}
    scan_data      = run_vulnerability_scan(token) if section in ('all', 'scan', 'report') else {'findings_count': 0}
    
    if section in ('all', 'patch'):
        apply_patch(token, software_id=1)
    
    if section in ('all', 'audit'):
        show_audit_log(token)
    
    if section in ('all', 'report'):
        generate_report(health_data, inventory_data, scan_data)
    
    print(color("\n\n  Demo complete! Application is running at http://localhost:5000", Colors.GREEN))
    print(color("  View API docs at: http://localhost:5000", Colors.GREEN))


if __name__ == '__main__':
    main()
