# CLAUDE.md — Static Application Security Testing

## Project Overview

A collection of self-contained, zero-dependency Python SAST scanners for source code
vulnerability detection, plus a Microsoft 365 SSPM scanner. Each scanner is a single
Python file that can be run standalone with no setup beyond Python 3.8+.

**Repository**: https://github.com/Krishcalin/Static-Application-Security-Testing
**License**: MIT
**Python**: 3.8+

## Scanner Inventory

| Scanner | Type | Version | Lines | Target | Dependencies |
|---------|------|---------|------:|--------|-------------|
| `java_scanner.py` | SAST | 4.0.0 | 3,696 | Java source, Maven/Gradle, WAR/JAR, Spring Boot | None |
| `php_scanner.py` | SAST | 4.0.0 | 848 | PHP source, `php.ini` | None |
| `python_scanner.py` | SAST | 4.0.0 | 1,231 | Python source, requirements/Pipfile/pyproject.toml | None |
| `mern_scanner.py` | SAST | 4.0.0 | 1,181 | JS/TS source, package.json, `.env` | None |
| `owasp_llm_scanner.py` | SAST | 1.0.0 | 1,998 | Python/JS AI & LLM apps (OWASP LLM Top 10) | None |
| `m365_scanner.py` | SSPM | 1.0.0 | 2,258 | Microsoft 365 + Entra ID (Graph API) | `requests` |

**Total**: 6 scanners, ~11,212 lines, 200+ SAST rules, 80+ dependency CVEs.

## Architecture Pattern (All Scanners)

Every scanner follows the same architecture:

1. **Module-level rule dicts** — list of `{id, category, name, severity, pattern, description, cwe, recommendation}`
2. **`Finding` class** — `rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve` (uses `__slots__`)
3. **Scanner class** with `SKIP_DIRS`, `SEVERITY_ORDER`, `SEVERITY_COLOR`, `RESET`, `BOLD` as class attrs
4. **Methods**: `scan_path`, `_scan_directory`, `_dispatch_file`, language-specific scan methods, `_sast_scan`, `_add`, `_vprint`, `_warn`, `summary`, `filter_severity`, `print_report`, `save_json`
5. **CLI**: `argparse` with `target`, `--json FILE`, `--severity`, `--verbose/-v`, `--version`
6. **Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise

### File Dispatch Pattern

```
scan_path(target)
  └─ _scan_directory(dir)
       └─ _dispatch_file(path)
            ├─ .java → _scan_java(path)
            ├─ .py   → _scan_python(path)
            ├─ .js   → _scan_js(path)
            ├─ .php  → _scan_php(path)
            ├─ pom.xml / build.gradle → _scan_deps(path)
            ├─ requirements.txt → _scan_deps(path)
            ├─ package.json → _scan_deps(path)
            ├─ .env  → _scan_env(path)
            └─ php.ini → _scan_phpini(path)
```

### SAST Scan Flow

```
_sast_scan(file_path, rules_list)
  for each line in file:
    for each rule in rules_list:
      if regex matches line:
        _add(Finding(...))
```

### Version Scanning (Dependency CVEs)

```
_parse_ver(s) → tuple of ints
_version_in_range(ver, range_str) → bool
  Handles: <, <=, >, >=, comma-separated conditions
```

## SAST Scanner Details

### Java Scanner (`java_scanner.py`) — v4.0.0

**Rule categories**: Insecure Deserialization, SQL Injection, Command Injection, Path Traversal, XSS, Hardcoded Credentials, Weak Cryptography (MD5/SHA-1/DES/ECB), XXE, SSRF, Open Redirect, Disabled SSL Validation, Log Injection (Log4Shell), Spring Boot Misconfigs.

**File types**: `.java`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `.war`/`.jar`/`.ear` (ZIP extraction), `web.xml`, `.properties`/`.yml`/`.yaml`.

**Dependency CVEs**: 9 (commons-collections, log4j, spring-core, struts2, jackson-databind, shiro, xstream, fastjson, h2).

**Rule ID prefix**: `JAVA-{CAT}-{NNN}`, `DEP-JAVA-CVE-{YYYY}-{NNNNN}`

### PHP Scanner (`php_scanner.py`) — v4.0.0

**Rule categories**: RCE, Command Injection, SQL Injection, Path Traversal/LFI/RFI, XSS, Unsafe Deserialization, File Upload, Hardcoded Credentials, Weak Crypto, Open Redirect, SSRF.

**File types**: `.php`, `.phtml`, `.php5`-`.php8`, `php.ini`.

**php.ini checks**: `display_errors`, `allow_url_include`, `allow_url_fopen`, `expose_php`, `register_globals`, `session.cookie_httponly`, `session.cookie_secure`, `disable_functions`.

**Rule ID prefix**: `PHP-{CAT}-{NNN}`, `PHPINI-{NNN}`

### Python Scanner (`python_scanner.py`) — v4.0.0

**Rule categories**: Insecure Deserialization, RCE, Command Injection, SQL Injection, Path Traversal, SSRF, SSTI, Open Redirect, Weak Crypto, XXE, Hardcoded Credentials/AI API Keys, Flask/Django Misconfigs, AI/Agentic patterns.

**File types**: `.py`, `.pyw`, `requirements.txt`, `Pipfile`, `pyproject.toml`.

**Dependency CVEs**: 18+ (Django, Flask, FastAPI, LangChain, transformers, torch, mlflow, gradio, cryptography, paramiko, Pillow, aiohttp, urllib3, Jinja2, requests, PyYAML).

**Rule ID prefix**: `PY-{CAT}-{NNN}`, `DEP-PY-CVE-{YYYY}-{NNNNN}`

### MERN Stack Scanner (`mern_scanner.py`) — v4.0.0

**Rule categories**: NoSQL Injection, Command Injection, Path Traversal, XSS, SQL Injection, SSRF, JWT Bypass, Prototype Pollution, Hardcoded Credentials, Insecure Deserialization, CORS/Helmet/Cookie Misconfigs, ReDoS.

**File types**: `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `package.json`, `.env`/`.env.*`.

**Dependency CVEs**: 20+ (minimist, ejs, lodash, jsonwebtoken, axios, mongoose, express, next, socket.io, ws, cross-spawn, path-to-regexp, tough-cookie, body-parser, multer, passport, node-fetch).

**Rule ID prefix**: `MERN-{CAT}-{NNN}`, `ENV-{NNN}`, `DEP-NODE-CVE-{YYYY}-{NNNNN}`

### OWASP LLM Top 10 Scanner (`owasp_llm_scanner.py`) — v1.0.0

**Rule sets**:
- `LLM_PYTHON_SAST_RULES` — 36 rules for `.py`/`.pyw`
- `LLM_JS_SAST_RULES` — 16 rules for `.js`/`.jsx`/`.ts`/`.tsx`
- `LLM_ENV_RULES` — 4 rules for `.env`
- `LLM_YAML_RULES` — 4 rules for `.yaml`/`.yml`
- `LLM_VULNERABLE_PACKAGES` — 13 Python LLM packages with CVEs
- `LLM_NPM_VULNERABLE_PACKAGES` — 3 npm LLM packages

**OWASP categories**: LLM01 (Prompt Injection), LLM02 (Info Disclosure), LLM03 (Supply Chain), LLM04 (Data Poisoning), LLM05 (Improper Output), LLM06 (Excessive Agency), LLM07 (System Prompt Leakage), LLM08 (Vector/Embedding), LLM09 (Misinformation), LLM10 (Unbounded Consumption).

**Rule ID prefix**: `LLM{NN}-{NNN}`, `LLM{NN}-JS-{NNN}`, `LLM{NN}-ENV-{NNN}`, `LLM{NN}-YAML-{NNN}`, `DEP-LLM-CVE-{YYYY}-{NNNNN}`, `LLM03-REQ-{NNN}`

## SSPM Scanner Details

### Microsoft 365 + Entra ID Scanner (`m365_scanner.py`) — v1.0.0

**Auth**: OAuth 2.0 Client Credentials flow (Entra ID App Registration).

**Required Graph API permissions**: `Policy.Read.All`, `Directory.Read.All`, `User.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`, `IdentityRiskyUser.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`, `SecurityEvents.Read.All`.

**Check categories** (12 groups, 50+ findings):
- Security Defaults (M365-SEC)
- Conditional Access (M365-CA) — MFA, legacy auth, risky sign-in
- MFA Registration (M365-MFA) — coverage, phishing-resistant methods
- Privileged Access (M365-PRIV) — Global Admin count, PIM, break-glass
- Password Policy (M365-PWD)
- App Registrations (M365-APP) — high-risk permissions, secret/cert hygiene
- Guest & External Access (M365-GUEST)
- Exchange Online (M365-EXO) — auto-forwarding, legacy protocols
- SharePoint Online (M365-SPO) — sharing, anonymous links
- Microsoft Teams (M365-TEAMS) — anonymous join, federation
- Audit Logging (M365-AUDIT)
- Identity Protection (M365-IDP) — risky users, risk policies

**Rule ID prefix**: `M365-{CAT}-{NNN}`

## Test Samples

Located in `tests/samples/`:

| File | Scanner(s) | Purpose |
|------|-----------|---------|
| `VulnerableApp.java` | java_scanner | SQLI, CMDI, DESER, XXE, XSS, CRED, CRYPTO, SSRF, Log4Shell |
| `pom.xml` | java_scanner | Maven dependency CVEs |
| `application.properties` | java_scanner | Spring Boot misconfigs |
| `vulnerable.php` | php_scanner | RCE, CMDI, SQLI, XSS, LFI, unserialize, open redirect |
| `php.ini` | php_scanner | All php.ini misconfiguration rules |
| `vulnerable_agent.py` | python_scanner, owasp_llm_scanner | 50+ Python SAST rules incl. AI/agentic |
| `requirements.txt` | python_scanner, owasp_llm_scanner | Known-vulnerable Python packages |
| `vulnerable_mern.js` | mern_scanner | NoSQL injection, CMDI, JWT bypass, prototype pollution |
| `package.json` | mern_scanner | 20 known-vulnerable npm packages |
| `.env` | mern_scanner | Weak secrets, DEBUG, CORS, DB credentials |

## Development Guidelines

### Adding New SAST Rules

1. Add regex pattern dict to the appropriate rules list at module level.
2. Follow ID pattern: `{LANG}-{CATEGORY}-{NNN}` (e.g., `JAVA-SQLI-001`).
3. Include: `id`, `name`, `category`, `severity`, `pattern` (regex), `description`, `recommendation`, `cwe`.
4. Test against sample files in `tests/samples/`.

### Adding New Dependency CVEs

1. Add to the `VULNERABLE_*` list at module level.
2. ID pattern: `DEP-{LANG}-CVE-{YYYY}-{NNNNN}`.
3. Include: `package`, `version_range`, `cve`, `severity`, `description`, `recommendation`.

### Conventions

- Single-file scanners — entire scanner in one `.py` file, no imports beyond stdlib.
- `__slots__` on Finding class for memory efficiency.
- ANSI colour codes for console output (CRITICAL=red, HIGH=yellow, MEDIUM=blue, LOW=green, INFO=white).
- HTML reports use Catppuccin Mocha dark theme (`#1a1b2e` bg, `#cdd6f4` text).
- Exit code 1 on CRITICAL/HIGH findings for CI/CD pipeline gating.
- `SKIP_DIRS` excludes `node_modules`, `.git`, `__pycache__`, `venv`, `.venv`, `build`, `dist`, `target`.

## Related Projects

| Project | Repo |
|---------|------|
| AWS CloudFormation + Terraform IaC | [AWS-Security-Scanner](https://github.com/Krishcalin/AWS-Security-Scanner) |
| Cisco IOS/IOS-XE Network Security | [Cisco-Network-Security](https://github.com/Krishcalin/Cisco-Network-Security) |
| Palo Alto PAN-OS Firewall | [PaloAlto-Network-Security](https://github.com/Krishcalin/PaloAlto-Network-Security) |
| Fortinet FortiGate Firewall | [Fortinet-Network-Security](https://github.com/Krishcalin/Fortinet-Network-Security) |
| ServiceNow SSPM | [SSPM-ServiceNow](https://github.com/Krishcalin/SSPM-ServiceNow) |
| SAP SuccessFactors SSPM | [SAP-SuccessFactors](https://github.com/Krishcalin/SAP-SuccessFactors) |
| Kubernetes KSPM | [Kubernetes-KSPM](https://github.com/Krishcalin/Kubernetes-Security-Posture-Management) |
| AI Security Posture Management | [AI-Secure-Posture-Management](https://github.com/Krishcalin/AI-Secure-Posture-Management) |
| OWASP API Security | [API-Security](https://github.com/Krishcalin/API-Security) |
| Cloud Detection & Response | [Cloud-Detection-Response](https://github.com/Krishcalin/Cloud-Detection-Response) |
| DAST Scanner | [Dynamic-Application-Security-Testing](https://github.com/Krishcalin/Dynamic-Application-Security-Testing) |
| Windows Red Teaming (MITRE ATT&CK) | [Windows-Red-Teaming](https://github.com/Krishcalin/Windows-Red-Teaming) |
