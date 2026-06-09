# Benchmark: HEAVEN vs. dvwa v1.10

Target: `http://localhost:8080`  ·  Image: `vulnerables/web-dvwa:latest`  ·  Duration: 32.6s

## Headline metrics

| Metric                       | Value |
|------------------------------|------:|
| Precision (TP / TP+FP)       | 0.0% |
| Recall (required GT only)    | 0.0% |
| Recall (all GT)              | 0.0% |
| F1                           | 0.0% |
| Required GT detected         | 0 / 10 |
| All GT detected              | 0 / 14 |
| Findings matching ground truth | 0 |
| Findings without GT match (potential FP) | 38 |

## Per-category recall

| Category | GT total | Detected | Recall | Findings emitted | Of which matched |
|----------|---------:|---------:|-------:|-----------------:|-----------------:|
| 403_bypass_path_manipulation |        0 |        0 |   0.0% |                1 |                0 |
| clickjacking_no_xfo |        0 |        0 |   0.0% |                1 |                0 |
| cmdi           |        2 |        0 |   0.0% |                0 |                0 |
| csp_missing    |        0 |        0 |   0.0% |                1 |                0 |
| csrf           |        1 |        0 |   0.0% |                0 |                0 |
| dangerous_http_method |        0 |        0 |   0.0% |                1 |                0 |
| file_upload    |        1 |        0 |   0.0% |                0 |                0 |
| hidden_parameter_discovered |        0 |        0 |   0.0% |                3 |                0 |
| host_header_injection |        0 |        0 |   0.0% |                1 |                0 |
| http_smuggling_indicator |        0 |        0 |   0.0% |                1 |                0 |
| idor           |        0 |        0 |   0.0% |                1 |                0 |
| lfi            |        2 |        0 |   0.0% |                0 |                0 |
| method_override_accepted |        0 |        0 |   0.0% |                3 |                0 |
| no_forward_secrecy |        0 |        0 |   0.0% |                1 |                0 |
| no_hsts        |        0 |        0 |   0.0% |                1 |                0 |
| no_permissions_policy |        0 |        0 |   0.0% |                1 |                0 |
| no_referrer_policy |        0 |        0 |   0.0% |                1 |                0 |
| no_x_content_type |        0 |        0 |   0.0% |                1 |                0 |
| open_redirect  |        1 |        0 |   0.0% |                0 |                0 |
| race_condition |        0 |        0 |   0.0% |                3 |                0 |
| request_smuggling |        0 |        0 |   0.0% |                1 |                0 |
| sensitive_file |        0 |        0 |   0.0% |               12 |                0 |
| server_version_disclosure |        0 |        0 |   0.0% |                1 |                0 |
| sqli           |        3 |        0 |   0.0% |                0 |                0 |
| unknown        |        0 |        0 |   0.0% |                1 |                0 |
| weak_auth      |        1 |        0 |   0.0% |                1 |                0 |
| xml_accepted   |        0 |        0 |   0.0% |                1 |                0 |
| xss            |        3 |        0 |   0.0% |                0 |                0 |

## Missed required vulnerabilities (benchmark failures)

- **dvwa-sqli-low-id** · `GET /vulnerabilities/sqli/` (param `id`) · sqli / critical / low
  - Direct $_GET['id'] interpolated into mysqli_query, no escaping.
- **dvwa-sqli-medium-id** · `POST /vulnerabilities/sqli/` (param `id`) · sqli / critical / medium
  - Numeric-only client-side check + mysql_real_escape_string — bypassable by integer payloads.
- **dvwa-sqli-blind-low-id** · `GET /vulnerabilities/sqli_blind/` (param `id`) · sqli / critical / low
  - Blind SQLi — output suppressed but boolean/time-based payloads work.
- **dvwa-xss-reflected-low-name** · `GET /vulnerabilities/xss_r/` (param `name`) · xss / high / low
  - Reflected XSS — name parameter echoed unescaped into HTML.
- **dvwa-xss-reflected-medium-name** · `GET /vulnerabilities/xss_r/` (param `name`) · xss / high / medium
  - str_replace('<script>') filter — bypassable by case variation or other tags.
- **dvwa-cmdi-low-ip** · `POST /vulnerabilities/exec/` (param `ip`) · cmdi / critical / low
  - shell_exec($_REQUEST['ip']) — direct OS command injection via ; or && separators.
- **dvwa-cmdi-medium-ip** · `POST /vulnerabilities/exec/` (param `ip`) · cmdi / critical / medium
  - Blacklist of ;,&&,| — bypassable with backticks, |, newline.
- **dvwa-lfi-low-page** · `GET /vulnerabilities/fi/` (param `page`) · lfi / high / low
  - include($_GET['page']) — full LFI, /etc/passwd readable.
- **dvwa-lfi-medium-page** · `GET /vulnerabilities/fi/` (param `page`) · lfi / high / medium
  - str_replace('../') applied — bypassable by ....// or absolute paths.
- **dvwa-csrf-low** · `GET /vulnerabilities/csrf/` (param `password_new`) · csrf / high / low
  - Password change accepts GET request, no anti-CSRF token.

## Findings without ground-truth match

These may be true positives (GT incomplete) or false positives. Review and either add to the GT file or investigate.

| URL | Vuln type | Param | Confidence |
|-----|-----------|-------|-----------:|
| http://localhost:8080/login.php | sensitive_file |  | 0.90 |
| http://localhost:8080/docs | sensitive_file |  | 0.90 |
| http://localhost:8080/config | sensitive_file |  | 0.90 |
| http://localhost:8080/.htpasswd | sensitive_file |  | 0.90 |
| http://localhost:8080/.htaccess | sensitive_file |  | 0.90 |
| http://localhost:8080/.gitignore | sensitive_file |  | 0.90 |
| http://localhost:8080/index.php | sensitive_file |  | 0.90 |
| http://localhost:8080/robots.txt | sensitive_file |  | 0.90 |
| http://localhost:8080/phpinfo.php | sensitive_file |  | 0.90 |
| http://localhost:8080/server-status | sensitive_file |  | 0.90 |
| http://localhost:8080/setup.php | sensitive_file |  | 0.90 |
| http://localhost:8080/README.md | sensitive_file |  | 0.90 |
| localhost:8080 | no_forward_secrecy |  | 0.95 |
| localhost:8080 | no_hsts |  | 0.97 |
| http://localhost:8080 | csp_missing |  | 0.98 |
| http://localhost:8080 | clickjacking_no_xfo |  | 0.98 |
| http://localhost:8080 | no_x_content_type |  | 0.98 |
| http://localhost:8080 | no_referrer_policy |  | 0.98 |
| http://localhost:8080 | no_permissions_policy |  | 0.98 |
| http://localhost:8080 | server_version_disclosure |  | 0.98 |
| http://localhost:8080/?phpinfo=2 | idor | phpinfo | 0.82 |
| http://localhost:8080/phpinfo.php | race_condition |  | 0.70 |
| http://localhost:8080/?phpinfo=1 | race_condition |  | 0.70 |
| http://localhost:8080/index.php?option=com_users | race_condition |  | 0.70 |
| http://localhost:8080 | request_smuggling |  | 0.60 |
| http://localhost:8080 | unknown |  | 0.90 |
| http://localhost:8080 | dangerous_http_method |  | 0.80 |
| http://localhost:8080 | host_header_injection |  | 0.90 |
| http://localhost:8080/server-status | 403_bypass_path_manipulation |  | 0.85 |
| http://localhost:8080 | http_smuggling_indicator |  | 0.65 |
| http://localhost:8080/phpinfo.php | method_override_accepted |  | 0.78 |
| http://localhost:8080 | xml_accepted |  | 0.65 |
| http://localhost:8080/phpinfo.php | hidden_parameter_discovered | jsonp | 0.72 |
| http://localhost:8080 | method_override_accepted |  | 0.78 |
| http://localhost:8080 | hidden_parameter_discovered | output | 0.72 |
| http://localhost:8080/?phpinfo=1 | method_override_accepted |  | 0.78 |
| http://localhost:8080/?phpinfo=1 | hidden_parameter_discovered | ref | 0.72 |
| http://localhost:8080 | no_rate_limit |  | 0.75 |

