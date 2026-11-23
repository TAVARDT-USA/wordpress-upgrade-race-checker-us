#!/usr/bin/env python3
"""
TAVARDT USA: WordPress Upgrade Race Condition & RCE Auditor (CLI)
Automated perimeter inspection utility for detecting exposure and execution risks
in transient WordPress upgrade directories (wp-content/upgrade/).
"""

import sys
import json
import urllib.request
import urllib.error
import ssl

def check_route(target_url, path):
    full_url = target_url.rstrip("/") + "/" + path.lstrip("/")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        full_url,
        headers={"User-Agent": "TAVARDT-WordPress-Race-Auditor/1.0 (+https://ag.tavardt.com/us/cybersecurity/)"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            status_code = response.getcode()
            body = response.read(2048).decode("utf-8", errors="ignore")
            is_index_of = "Index of" in body or "<title>Index of" in body
            return {
                "path": path,
                "url": full_url,
                "status": status_code,
                "accessible": True,
                "directory_listing": is_index_of,
                "risk": "CRITICAL" if is_index_of or status_code == 200 else "LOW"
            }
    except urllib.error.HTTPError as e:
        return {
            "path": path,
            "url": full_url,
            "status": e.code,
            "accessible": False,
            "directory_listing": False,
            "risk": "PROTECTED" if e.code in [403, 404] else "WARNING"
        }
    except Exception as e:
        return {
            "path": path,
            "url": full_url,
            "status": 0,
            "accessible": False,
            "directory_listing": False,
            "risk": "CONNECTION_ERROR",
            "error": str(e)
        }

def audit_wordpress(target_url):
    paths = [
        "wp-content/upgrade/",
        "wp-content/upgrade/test.php",
        "wp-content/uploads/",
        "wp-content/uploads/test.php"
    ]
    
    results = []
    for p in paths:
        results.append(check_route(target_url, p))
    
    upgrade_dir = next((r for r in results if r["path"] == "wp-content/upgrade/"), None)
    is_vulnerable = False
    if upgrade_dir and (upgrade_dir["directory_listing"] or upgrade_dir["status"] == 200):
        is_vulnerable = True
        
    assessment = {
        "target": target_url,
        "is_vulnerable": is_vulnerable,
        "posture": "VULNERABLE" if is_vulnerable else "PROTECTED",
        "routes": results,
        "remediation": [
            "Define WP_TEMP_DIR outside the public web root in wp-config.php: define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');",
            "Deny PHP script execution in wp-content/upgrade/ and wp-content/uploads/ via Nginx or Apache.",
            "Configure a Cloudflare WAF custom rule to drop incoming requests targeting /wp-content/upgrade/.",
            "Enable DISALLOW_FILE_MODS to enforce deployment strictly via automated CI/CD pipelines."
        ]
    }
    return assessment

def print_remediation():
    print("""
================================================================================
  ARCHITECTURAL REMEDIATION DIRECTIVES: WORDPRESS UPGRADE RACE CONDITION
================================================================================
1. Hardening in wp-config.php:
   Add prior to "/* That's all, stop editing! */":
   define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
   define('DISALLOW_FILE_MODS', true);
   define('DISALLOW_FILE_EDIT', true);

2. Edge Blocking in Nginx (nginx.conf):
   location ~* /wp-content/upgrade/ {
       deny all;
       return 403;
   }
   location ~* ^/wp-content/(uploads|upgrade)/.*\.php$ {
       deny all;
       return 403;
   }

3. Edge Blocking in Apache (.htaccess inside wp-content/upgrade/):
   <FilesMatch "\.(php|phtml|php[0-9]|sh|cgi)$">
       Require all denied
   </FilesMatch>
   Options -Indexes
================================================================================
""")

def main():
    if len(sys.argv) < 2:
        print("Usage: python wordpress_upgrade_checker.py <URL_OR_DOMAIN> [--json] [--remediate]")
        print("Example: python wordpress_upgrade_checker.py https://enterprise-site.com")
        sys.exit(1)
        
    target = sys.argv[1].strip()
    if target in ["--help", "-h"]:
        print("Usage: python wordpress_upgrade_checker.py <URL_OR_DOMAIN> [--json] [--remediate]")
        sys.exit(0)
        
    if target == "--remediate":
        print_remediation()
        sys.exit(0)
        
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
        
    is_json = "--json" in sys.argv
    show_remediate = "--remediate" in sys.argv
    
    data = audit_wordpress(target)
    
    if is_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
        
    print("=" * 80)
    print("  TAVARDT USA: WORDPRESS UPGRADE RACE CONDITION AUDITOR")
    print("=" * 80)
    print(f"Target: {target}")
    print(f"Overall Posture: {data['posture']}")
    print("-" * 80)
    print("Inspected Routes:")
    for r in data["routes"]:
        status = r["status"] if r["status"] != 0 else "Connection Failure"
        list_flag = " [DIRECTORY LISTING DETECTED]" if r.get("directory_listing") else ""
        print(f" * [{r['risk']}] {r['path']} -> HTTP {status}{list_flag}")
        
    print("-" * 80)
    if data["is_vulnerable"]:
        print("[CRITICAL ALERT] Target displays exposed /wp-content/upgrade/ directory.")
        print("Attackers can exploit concurrency windows to execute transient PHP scripts.")
    else:
        print("[CONFORMANT] Directory /wp-content/upgrade/ is strictly protected against direct access.")
        
    if show_remediate:
        print_remediation()
    else:
        print("Tip: Run with --remediate to inspect remediation configuration blocks.")
    print("=" * 80)

if __name__ == "__main__":
    main()
