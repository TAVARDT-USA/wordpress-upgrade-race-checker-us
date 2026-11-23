# WordPress Upgrade Race Condition & RCE Auditor | TAVARDT USA

> Enterprise Resilience Audit against WordPress Upgrade Race Conditions, Transient Directory Exposure, and Remote Code Execution (RCE)

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: CIS WordPress](https://img.shields.io/badge/Security-CIS%20WordPress%20%7C%20OWASP-red.svg)](https://owasp.org/)

## Vulnerability Overview & Defensive Architecture

The standard component update workflow in WordPress (core, themes, and plugins) orchestrated by `class-wp-upgrader.php` downloads archive packages in ZIP format and extracts them into the temporary directory `wp-content/upgrade/` via `unzip_file()`.

During the time window between archive extraction on disk and atomic directory relocation to destination folders, a critical race condition opens inside the public web root. If the web server lacks perimeter restriction rules or Web Application Firewall (WAF) filtering, unauthenticated requests can directly reach extracted files in `wp-content/upgrade/`. If the PHP runtime (FastCGI/PHP-FPM) compiles scripts in that directory, attackers can trigger arbitrary Remote Code Execution (RCE) under the web server privileges.

This repository provides an interactive in-browser diagnostic tool and a zero-dependency companion Python CLI scanner for automated security audits.

## Interactive Web Application

Access the live web tool hosted on GitHub Pages:
[https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/](https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/)

Core features of the web application:
* Real-time perimeter reachability and network latency verification.
* Transient `wp-content/upgrade/` exposure and directory listing detection.
* Comparative architectural matrix (Vulnerable vs. Hardened WordPress topology).
* Automated defense configuration generator for Nginx, Apache (.htaccess), wp-config.php, and Cloudflare WAF.
* Responsive interface optimized for mobile and desktop viewports.

## Python CLI Scanner Usage

The companion script `wordpress_upgrade_checker.py` requires no third-party packages and runs in any Python 3.8+ environment:

```bash
# Run direct audit against a domain
python wordpress_upgrade_checker.py https://enterprise-site.com

# Run audit in JSON format for CI/CD and DevSecOps pipelines
python wordpress_upgrade_checker.py https://enterprise-site.com --json

# Display remediation and hardening configuration blocks directly
python wordpress_upgrade_checker.py --remediate
```

## Architectural Controls & Defensive Mitigations

To definitively eliminate race condition and RCE threat surfaces in WordPress, enforce defense-in-depth across 4 layers:

1. **Transient Directory Isolation (wp-config.php):**
   Configure `WP_TEMP_DIR` to point to an external path isolated outside the public `DocumentRoot`:
   ```php
   define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
   define('DISALLOW_FILE_MODS', true);
   define('DISALLOW_FILE_EDIT', true);
   ```

2. **Perimeter Blocking in Nginx (nginx.conf):**
   Deny incoming HTTP requests targeting the upgrade folder and prohibit `.php` compilation in content paths:
   ```nginx
   location ~* /wp-content/upgrade/ {
       deny all;
       return 403;
   }
   location ~* ^/wp-content/(uploads|upgrade)/.*\.php$ {
       deny all;
       return 403;
   }
   ```

3. **Apache Hardening (.htaccess):**
   Enforce strict rules in `wp-content/upgrade/.htaccess`:
   ```apache
   <FilesMatch "\.(php|phtml|php[0-9]|sh|cgi)$">
       Require all denied
   </FilesMatch>
   Options -Indexes
   ```

4. **Cloudflare WAF Custom Rule:**
   Create an edge rule dropping any request matching `(http.request.uri.path contains "/wp-content/upgrade/")`.

## Official Portals

* **TAVARDT USA Corporate Portal:** [https://ag.tavardt.com/us/](https://ag.tavardt.com/us/)
* **Cybersecurity Services:** [https://ag.tavardt.com/us/cybersecurity/](https://ag.tavardt.com/us/cybersecurity/)
* **Defensive Tools Hub:** [https://tools.tavardt.com/us/](https://tools.tavardt.com/us/)
* **GitHub Organization:** [https://github.com/TAVARDT-USA](https://github.com/TAVARDT-USA)

## License

Distributed under the MIT License. See `LICENSE` for more information.
