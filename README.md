<p align="center">
  <a href="https://ag.tavardt.com/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# WordPress Upgrade Race Condition Hardening & Audit Hub

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Vulnerability](https://img.shields.io/badge/Vulnerability-Race%20Condition-red.svg)](https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Technical engineering specification, automated hardening blueprints, and deterministic CLI auditing utility for neutralizing the WordPress Upgrade Race Condition and Remote Code Execution (RCE) vulnerability.

***

## Technical Summary: The Upgrade Race Condition Flaw

WordPress powers over 40 percent of the web. During core, theme, and plugin update cycles, the platform unpacks ZIP archives into a temporary directory before verifying and deploying files to their final destinations.

By default, WordPress extracts these archives into `wp-content/upgrade/`, a location residing directly inside the public DocumentRoot.

When web servers allow PHP script execution within content subdirectories, an attacker can trigger newly unpacked files during the extraction time window:
* The attacker monitors or triggers an update cycle on target sites.
* Newly uncompressed PHP files become executable prior to final file permission enforcement.
* Direct HTTP requests to these transient files trigger immediate Remote Code Execution (RCE) under the web server user identity (`www-data` or `nginx`).

This repository provides production-tested server configurations, defense-in-depth isolation blueprints, and a deterministic local Python CLI auditor (`audit_wp_race.py`) to verify perimeter defenses.

***

## Key Attack Surfaces in WordPress Content Directories

### 1. The Public `wp-content/upgrade/` Extraction Path
The primary weakness stems from locating transient decompression directories inside web-accessible storage:
* **The Vulnerability Window:** Large archive extraction can take several seconds on shared or busy servers.
* **The Exploitation Path:** An adversary issues rapid concurrent HTTP requests targeting unpackaged files before cleanup routines execute.
* **The Defensive Mandate:** Block all public HTTP access to `wp-content/upgrade/` and relocate the decompression path entirely outside the DocumentRoot.

### 2. Unrestricted PHP Execution in Upload Directories
Web servers frequently forward all `.php` file requests to FastCGI/PHP-FPM processors regardless of directory location:
* **The Vulnerability Window:** Upload and upgrade folders require write permissions for media handling and updates.
* **The Exploitation Path:** Combining write permissions with executable script execution creates persistent arbitrary execution risks.
* **The Defensive Mandate:** Explicitly deny PHP execution within `uploads`, `upgrade`, `languages`, and `mu-plugins` directories at the web server layer.

### 3. Exposed Directory Listings (Index Of)
Misconfigured web servers that lack index suppression expose directory contents publicly:
* **The Vulnerability Window:** Attackers can browse temporary update directories in real time to identify newly extracted file names.
* **The Defensive Mandate:** Disable automatic directory indexing globally across web server virtual hosts.

***

## Production Hardening Blueprints

Apply these verified mitigation configurations to protect live production environments:

### 1. Nginx Server Hardening (`nginx.conf`)
Blocks access to upgrade directories and disables script execution in content folders:

```nginx
# 1. Deny all direct access to transient upgrade directories
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

# 2. Prevent PHP execution inside static content paths
location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### 2. Apache Server Protection (`.htaccess`)
Place this configuration inside `/wp-content/upgrade/.htaccess` and `/wp-content/uploads/.htaccess`:

```apache
# Deny execution of all script extensions
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>

# Disable directory listing
Options -Indexes
```

### 3. WordPress Core Configuration (`wp-config.php`)
Relocates temporary files outside the public DocumentRoot and restricts file modifications:

```php
/* Relocate WordPress temporary files outside public web root */
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');

/* Restrict in-dashboard file editing and file modifications */
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### 4. Cloudflare WAF Edge Defense Rule
Blocks unauthorized probing targeting sensitive WordPress directories at the network edge:

```text
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
Action: Block (Drop connection immediately)
```

***

## Deterministic CLI Audit Utility

Web browser environments enforce strict sandbox and CORS limitations that prevent raw socket evaluation of HTTP status codes and redirection flows. To deliver verifiable security evaluations, TAVARDT provides a deterministic Python auditing tool designed for terminal execution and automated deployment gates.

### Static and Active Inspection Engine

The CLI utility (`audit_wp_race.py`) executes a multi-stage audit sequence:
* **URL Sanitization & Reachability:** Validates input structure, normalizes host protocols, and verifies connectivity.
* **WordPress Fingerprinting:** Confirms target architecture via REST API markers, canonical assets, and login endpoints.
* **SPA Catch-All Detection:** Distinguishes genuine 403/404 blocks from generic Single Page Application routing fallbacks.
* **Targeted Route Probing:** Probes `/wp-content/upgrade/` and executable test files to verify server rejection.
* **Deterministic Scoring:** Issues an automated risk score ranging from 100 (Hardened) to 25 (Vulnerable).

### Terminal Usage

Download and execute the audit utility directly against your target WordPress domain:

```bash
# 1. Download official audit utility
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/wordpress-upgrade-race-checker-us/main/audit_wp_race.py

# 2. Run direct audit against target domain
python audit_wp_race.py https://your-domain.com

# 3. Output results in machine-readable JSON format
python audit_wp_race.py https://your-domain.com -j
```

***

## Frequently Asked Questions (Technical & Architecture FAQ)

### 1. What triggers the WordPress upgrade race condition vulnerability?
During core, theme, or plugin update routines, WordPress extracts ZIP packages into the temporary directory `wp-content/upgrade/` before verifying file integrity and relocating them to permanent paths. If web server rules permit script execution in content folders, an attacker can request newly uncompressed PHP files during this extraction window, achieving Remote Code Execution under web server privileges.

### 2. Why is blocking direct HTTP access to the upgrade folder essential?
The `wp-content/upgrade/` directory is designed exclusively for local server processes during internal update routines. Public HTTP clients have no legitimate operational need to access this path, and permitting external requests exposes transient build files and temporary scripts to exploitation.

### 3. How does relocating WP_TEMP_DIR outside the DocumentRoot neutralize this risk?
Defining `WP_TEMP_DIR` outside the web root (for instance, in `/var/www/tmp/` instead of `/wp-content/upgrade/`) ensures that uncompressed files are physically unreachable via web requests. Even if an attacker identifies temporary file names, the web server cannot serve or execute files located outside DocumentRoot boundaries.

### 4. How do Nginx and Apache prevent script execution in content subdirectories?
Nginx configurations apply regular expression location rules returning HTTP 403 for any request containing `.php` inside `uploads` or `upgrade` paths. Apache configurations utilize `.htaccess` files combining `<FilesMatch>` directives that deny all script execution alongside `Options -Indexes` to stop directory listing.

### 5. Does the deterministic Python audit utility disrupt live WordPress sites during evaluation?
No. The CLI utility operates as a passive diagnostic scanner transmitting standard HTTP GET and HEAD requests to evaluate response codes. It verifies whether temporary paths return HTTP 403 or 404 versus an open HTTP 200 state, diagnosing perimeter posture without altering files or database records.

***

## Compliance Frameworks & Security Standards

Defensive architecture and software security controls aligned with NIST SP 800-53, CMMC 2.0, SOC 2 Type II, and Federal Cybersecurity Standards.

***

## 4. Online Interactive Hub

Access the production interactive guide:  
[https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/](https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/)

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
