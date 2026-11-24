# WordPress Upgrade Race Condition Hardening & Audit Hub

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Vulnerability](https://img.shields.io/badge/Vulnerability-Race%20Condition-red.svg)](https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Official repository and technical reference for mitigating the **WordPress Upgrade Race Condition & Remote Code Execution (RCE)** vulnerability.

***

## 1. Vulnerability Overview

During core, theme, and plugin updates, WordPress temporarily extracts ZIP archives into `wp-content/upgrade/` before files are verified and moved to production paths.

When server configurations allow execution of PHP scripts in content subdirectories, an attacker can trigger newly unpacked files during the extraction window. This enables Remote Code Execution (RCE) with the permissions of the web server user.

### Key Risk Indicators:
* Public HTTP accessibility of `wp-content/upgrade/`
* PHP execution enabled in uploads and upgrade folders
* Missing `WP_TEMP_DIR` directive outside the DocumentRoot

***

## 2. Deterministic Audit via CLI

Because web browsers impose CORS and sandbox restrictions that prevent deep socket inspection, use the official Python audit tool directly in your terminal or CI/CD pipeline:

```bash
# 1. Download official audit utility
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/wordpress-upgrade-race-checker-us/main/audit_wp_race.py

# 2. Run direct audit against your domain
python audit_wp_race.py https://your-domain.com
```

### Supported Parameters:
* Positional target argument or `-u https://target-domain.com`
* `-t <seconds>` : Timeout in seconds (default: 5)
* `-j` : JSON format output for automated pipelines

***

## 3. Mitigation Blueprints

### A. Nginx (`nginx.conf`)
```nginx
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### B. Apache (`.htaccess`)
```apache
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>
Options -Indexes
```

### C. WordPress (`wp-config.php`)
```php
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### D. Cloudflare WAF Rule
```cloudflare
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
```

***

## 4. Online Interactive Hub

Access the production interactive guide:  
[https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/](https://tavardt-usa.github.io/wordpress-upgrade-race-checker-us/)

***

## Governance and Sovereignty

* **Sovereign Unit**: [TAVARDT United States](https://ag.tavardt.com/) (`TAVARDT-USA`)
* **Core Standards**: [00-core Governance](https://github.com/TAVARDT-USA/00-core)
* **Diagnostic Portal**: [TAVARDT US Diagnostic Suite](https://tools.tavardt.com/)
* **Enterprise Security**: [TAVARDT US Cybersecurity](https://ag.tavardt.com/cybersecurity/)

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
