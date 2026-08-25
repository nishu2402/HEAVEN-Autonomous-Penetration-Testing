"""
HEAVEN — CVE Mapper
Maps discovered services to CPE strings and correlates with known vulnerabilities.
Includes fuzzy CPE matching, version-range CVE database, and zero-day heuristics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.utils.cvss import severity_from_score
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.mapper")


def _score_and_severity(cvss: Any, fallback_sev: str) -> tuple[float, str]:
    """Normalise a CVE record's score + severity so they never disagree.

    Returns ``(rounded_base_score, band)`` to store on the finding. Two things
    matter for a genuinely per-finding CVSS in the report/UI:

    * the real base score is emitted under the canonical ``cvss_base`` key, so
      the ML scorer (``feature_engine``) and the report resolver
      (``utils.cvss.objective_base_score``) read the SAME real number instead
      of collapsing every ``vulnerable_service`` finding onto the KB class
      "typical" constant (7.5);
    * the severity *band* follows that objective score — a curated DB sometimes
      labels an 8.1 as "critical" when the CVSS band is "high", which shows up
      in the report as an inconsistent "Critical / 8.1" row. Deriving the band
      from the score keeps the two columns consistent.

    When no usable score is present (0 / out of range) the caller's curated
    severity is kept and the base score is 0.0 (the resolver then falls back to
    the class taxonomy exactly as before).
    """
    try:
        c = float(cvss)
    except (TypeError, ValueError):
        c = 0.0
    if 0.0 < c <= 10.0:
        return round(c, 1), severity_from_score(c)
    return 0.0, fallback_sev

# ── CPE vendor/product table ──

CPE_MAP: dict[str, list[tuple[str, str]]] = {
    "ssh":           [("openbsd", "openssh")],
    "http":          [("apache", "http_server"), ("nginx", "nginx"), ("microsoft", "iis"),
                      ("lighttpd", "lighttpd"), ("openresty", "openresty")],
    "https":         [("apache", "http_server"), ("nginx", "nginx"), ("microsoft", "iis"),
                      ("lighttpd", "lighttpd"), ("openresty", "openresty")],
    "ftp":           [("vsftpd", "vsftpd"), ("proftpd", "proftpd"), ("pureftpd", "pure-ftpd"),
                      ("filezilla", "filezilla_server")],
    "sftp":          [("openbsd", "openssh")],
    "mysql":         [("oracle", "mysql"), ("mariadb", "mariadb_server")],
    "postgresql":    [("postgresql", "postgresql")],
    "redis":         [("redis", "redis")],
    "mongodb":       [("mongodb", "mongodb")],
    "mssql":         [("microsoft", "sql_server")],
    "smtp":          [("postfix", "postfix"), ("exim", "exim"), ("sendmail", "sendmail"),
                      ("microsoft", "exchange_server")],
    "smtps":         [("postfix", "postfix"), ("exim", "exim")],
    "imap":          [("dovecot", "dovecot"), ("courier", "courier-imap")],
    "imaps":         [("dovecot", "dovecot")],
    "pop3":          [("dovecot", "dovecot"), ("courier", "courier-pop3")],
    "rdp":           [("microsoft", "remote_desktop_protocol")],
    "vnc":           [("realvnc", "vnc_server"), ("tightvnc", "tightvnc"), ("ultravnc", "ultravnc")],
    "telnet":        [("gnu", "inetutils"), ("mit", "ktelnet")],
    "ldap":          [("openldap", "openldap"), ("microsoft", "active_directory")],
    "ldaps":         [("openldap", "openldap"), ("microsoft", "active_directory")],
    "smb":           [("samba", "samba"), ("microsoft", "windows")],
    "nfs":           [("linux", "nfs"), ("apple", "os_x")],
    "docker":        [("docker", "docker")],
    "kubernetes":    [("kubernetes", "kubernetes")],
    "elasticsearch": [("elastic", "elasticsearch")],
    "kibana":        [("elastic", "kibana")],
    "logstash":      [("elastic", "logstash")],
    "zookeeper":     [("apache", "zookeeper")],
    "kafka":         [("apache", "kafka")],
    "rabbitmq":      [("pivotal_software", "rabbitmq"), ("rabbitmq", "rabbitmq")],
    "memcached":     [("danga", "memcached"), ("memcached", "memcached")],
    "cassandra":     [("apache", "cassandra")],
    "couchdb":       [("apache", "couchdb")],
    "jenkins":       [("jenkins", "jenkins")],
    "jira":          [("atlassian", "jira")],
    "confluence":    [("atlassian", "confluence")],
    "gitlab":        [("gitlab", "gitlab")],
    "tomcat":        [("apache", "tomcat")],
    "jboss":         [("redhat", "jboss_enterprise_application_platform")],
    "weblogic":      [("oracle", "weblogic_server")],
    "websphere":     [("ibm", "websphere_application_server")],
    "glassfish":     [("oracle", "glassfish_server")],
    "wordpress":     [("wordpress", "wordpress")],
    "drupal":        [("drupal", "drupal")],
    "joomla":        [("joomla", "joomla\\!")],
    "phpmyadmin":    [("phpmyadmin", "phpmyadmin")],
    "cpanel":        [("cpanel", "cpanel")],
    "plesk":         [("plesk", "plesk")],
    "openssl":       [("openssl", "openssl")],
    "php":           [("php", "php")],
    "nodejs":        [("nodejs", "node.js")],
    "python":        [("python", "python")],
    "ruby":          [("ruby-lang", "ruby")],
    "java":          [("oracle", "jdk"), ("oracle", "jre")],
    "struts":        [("apache", "struts")],
    "spring":        [("vmware", "spring_framework"), ("pivotal_software", "spring_framework")],
    "log4j":         [("apache", "log4j")],
    "shiro":         [("apache", "shiro")],
    "solr":          [("apache", "solr")],
    "hadoop":        [("apache", "hadoop")],
}

# ── Inline CVE database: service → list of CVE records with version ranges ──

@dataclass
class CVERecord:
    cve_id: str
    title: str
    severity: str
    cvss: float
    affected_versions: list[str]         # exact versions or "<=X.Y.Z" / "X.Y.Z-X.Y.W"
    references: list[str] = field(default_factory=list)
    cwe: str = ""
    exploit_available: bool = False


# Format: version string may be:
#   "exact"     → exact match
#   "<=X.Y.Z"   → up to and including
#   ">=X.Y.Z"   → from and including
#   "<X.Y.Z"    → strictly less than
#   "X.Y.Z-A.B.C" → inclusive range
INLINE_CVE_DB: dict[str, list[CVERecord]] = {
    "openssh": [
        CVERecord("CVE-2023-38408", "OpenSSH ssh-agent RCE via forwarded agent",
                  # The vulnerable code path is ssh-agent's PKCS#11 provider, added
                  # in OpenSSH 5.4 — older releases (e.g. 4.7p1) predate it, so a
                  # bare "<=9.3p1" would falsely flag them.
                  "critical", 9.8, [">=5.4", "<=9.3p1"], exploit_available=True, cwe="CWE-78"),
        CVERecord("CVE-2023-51385", "OpenSSH shell metacharacter injection in ProxyCommand",
                  "high", 7.5, ["<=9.6"], cwe="CWE-78"),
        CVERecord("CVE-2024-6387", "OpenSSH regreSSHion RCE (signal handler race condition)",
                  "critical", 8.1, ["<=9.7p1", ">=8.5p1"], exploit_available=True, cwe="CWE-364"),
        CVERecord("CVE-2021-41617", "OpenSSH privilege escalation via AuthorizedKeysCommand",
                  "high", 7.0, [">=6.2", "<=8.8"], cwe="CWE-269"),
        CVERecord("CVE-2020-15778", "OpenSSH scp shell injection via filenames",
                  "high", 7.8, ["<=8.4"], exploit_available=True, cwe="CWE-78"),
        CVERecord("CVE-2019-6111", "OpenSSH scp malicious server overwrites local files",
                  "medium", 5.9, ["<=7.9"], cwe="CWE-22"),
        CVERecord("CVE-2018-15473", "OpenSSH username enumeration via timing oracle",
                  "medium", 5.3, ["<=7.7"], exploit_available=True, cwe="CWE-200"),
        CVERecord("CVE-2016-20012", "OpenSSH username enumeration via keyboard-interactive auth",
                  "medium", 5.3, ["<=8.0"], cwe="CWE-200"),
        CVERecord("CVE-2016-10010", "OpenSSH privilege escalation via socket forwarding",
                  "high", 7.0, ["7.2p2-7.4"], cwe="CWE-269"),
    ],
    "apache_http_server": [
        CVERecord("CVE-2021-41773", "Apache path traversal and RCE (mod_cgi)",
                  "critical", 9.8, ["2.4.49"], exploit_available=True, cwe="CWE-22"),
        CVERecord("CVE-2021-42013", "Apache path traversal bypass (second variant)",
                  "critical", 9.8, ["2.4.49", "2.4.50"], exploit_available=True, cwe="CWE-22"),
        # The 2.4-era defects below live in code paths (mod_http2, mod_lua,
        # mod_proxy rewrites) that only exist in the 2.4 line, so each carries an
        # explicit >=2.4.0 floor — without it a bare "<=2.4.x" ceiling also
        # matched ancient 2.2/2.0 servers (e.g. Metasploitable's 2.2.8), a false
        # positive of a modern-branch CVE on legacy software.
        CVERecord("CVE-2022-31813", "Apache HTTP request smuggling mod_proxy",
                  "high", 7.5, [">=2.4.0", "<=2.4.53"], cwe="CWE-444"),
        CVERecord("CVE-2022-22720", "Apache HTTP request smuggling (incomplete fix)",
                  "high", 7.5, [">=2.4.0", "<=2.4.52"], cwe="CWE-444"),
        CVERecord("CVE-2022-22721", "Apache SSRF via mod_lua",
                  "critical", 9.8, [">=2.4.0", "<=2.4.52"], cwe="CWE-918"),
        CVERecord("CVE-2021-44224", "Apache server-side request forgery in forward proxy",
                  "high", 8.2, [">=2.4.0", "<=2.4.51"], cwe="CWE-918"),
        CVERecord("CVE-2021-40438", "Apache SSRF in mod_proxy",
                  "critical", 9.0, [">=2.4.0", "<=2.4.48"], exploit_available=True, cwe="CWE-918"),
        CVERecord("CVE-2020-13950", "Apache mod_proxy_http NULL pointer dereference DoS",
                  "high", 7.5, [">=2.4.0", "<=2.4.46"], cwe="CWE-476"),
        CVERecord("CVE-2019-10082", "Apache mod_http2 read-after-free",
                  "high", 7.5, [">=2.4.17", "<=2.4.39"], cwe="CWE-416"),
        # These two genuinely span the 2.2 AND 2.4 lines, so both branch windows
        # are listed explicitly (2.2.8 is a real positive; a patched 2.4.30 is not).
        CVERecord("CVE-2017-7679", "Apache mod_mime buffer overread",
                  "critical", 9.8, ["2.2.0-2.2.34", "2.4.0-2.4.25"], cwe="CWE-125"),
        CVERecord("CVE-2017-9798", "Optionsbleed: Apache OPTIONS info disclosure",
                  "medium", 5.9, ["2.2.0-2.2.34", "2.4.0-2.4.27"], cwe="CWE-416"),
    ],
    "nginx": [
        CVERecord("CVE-2021-23017", "Nginx resolver off-by-one heap write",
                  "critical", 9.8, ["<=1.20.0"], exploit_available=True, cwe="CWE-193"),
        CVERecord("CVE-2019-20372", "Nginx HTTP request smuggling via invalid Transfer-Encoding",
                  "medium", 5.3, ["<=1.17.6"], cwe="CWE-444"),
        CVERecord("CVE-2019-9511", "Nginx HTTP/2 request flooding DoS (Data Dribble)",
                  "high", 7.5, ["<=1.16.0"], cwe="CWE-400"),
        CVERecord("CVE-2018-16843", "Nginx HTTP/2 excessive memory allocation",
                  "high", 7.5, ["<=1.15.5"], cwe="CWE-400"),
        CVERecord("CVE-2017-7529", "Nginx integer overflow in range filter",
                  "medium", 5.3, ["<=1.13.2"], exploit_available=True, cwe="CWE-190"),
        CVERecord("CVE-2016-0742", "Nginx resolver invalid pointer dereference",
                  "high", 7.5, ["<=1.9.10"], cwe="CWE-476"),
    ],
    "microsoft_iis": [
        CVERecord("CVE-2017-7269", "IIS 6.0 WebDAV buffer overflow RCE",
                  "critical", 10.0, ["6.0"], exploit_available=True, cwe="CWE-119"),
        CVERecord("CVE-2021-31166", "IIS HTTP Protocol Stack RCE",
                  "critical", 9.8, ["<=10.0"], exploit_available=True, cwe="CWE-416"),
        CVERecord("CVE-2022-21907", "IIS HTTP Protocol Stack RCE (worm-level)",
                  "critical", 9.8, ["<=10.0.19041"], exploit_available=True, cwe="CWE-416"),
    ],
    "mysql": [
        CVERecord("CVE-2023-21980", "MySQL Server DOS via Group Replication",
                  "high", 7.7, ["<=8.0.32"], cwe="CWE-400"),
        CVERecord("CVE-2022-21417", "MySQL Server InnoDB info disclosure",
                  "medium", 4.9, ["<=8.0.28", "<=5.7.37"], cwe="CWE-200"),
        # NOTE: CVE-2021-2471 (MySQL Connector/J SSRF) was intentionally removed —
        # it is a JDBC *client driver* CVE, not a MySQL Server flaw. HEAVEN only
        # ever fingerprints the server (port 3306 banner), never the connector, so
        # attaching it to a server produced a guaranteed false positive on every
        # MySQL <= 8.0.26 in the wild. Connector/J is out of scope for a network scan.
        CVERecord("CVE-2016-6662", "MySQL remote code execution via config file injection",
                  "critical", 9.8, ["<=5.7.14", "<=5.6.32", "<=5.5.51"],
                  exploit_available=True, cwe="CWE-264"),
        CVERecord("CVE-2012-2122", "MySQL authentication bypass (timing)",
                  "high", 7.5, ["<=5.6.5"], exploit_available=True, cwe="CWE-287"),
    ],
    "mariadb_server": [
        CVERecord("CVE-2023-5157", "MariaDB remote DoS via crafted SQL",
                  "high", 7.5, ["<=10.11.5", "<=10.6.15", "<=10.5.22"], cwe="CWE-400"),
        CVERecord("CVE-2022-32088", "MariaDB server crash via multibyte character",
                  "high", 7.5, ["<=10.9.3"], cwe="CWE-400"),
        CVERecord("CVE-2021-46667", "MariaDB crash in UPDATE with aggregate in ORDER BY",
                  "medium", 5.5, ["<=10.6.5"], cwe="CWE-400"),
    ],
    "redis": [
        CVERecord("CVE-2023-28856", "Redis OBJECT ENCODING crash with invalid encoding",
                  "medium", 5.5, ["<=7.0.10", "<=6.2.11"], cwe="CWE-476"),
        CVERecord("CVE-2022-24834", "Redis heap overflow in Lua scripting library",
                  "high", 8.8, ["<=7.0.11", "<=6.2.13", "<=6.0.20"], cwe="CWE-122"),
        CVERecord("CVE-2022-0543", "Redis Lua sandbox escape (Debian/Ubuntu packages)",
                  "critical", 10.0, ["all_debian_packages"], exploit_available=True, cwe="CWE-862"),
        CVERecord("CVE-2021-32762", "Redis integer overflow in COPY / OBJECT ENCODING",
                  "critical", 9.8, ["<=6.2.5", "<=6.0.15"], cwe="CWE-190"),
        CVERecord("CVE-2021-29477", "Redis integer overflow in STRALGO LCS",
                  "critical", 9.8, ["<=6.0.13", ">=6.0", "<=6.2.3"], cwe="CWE-190"),
        CVERecord("CVE-2019-10192", "Redis heap buffer overflow in HyperLogLog",
                  "high", 8.8, ["<=3.2.12", "<=4.0.14", "<=5.0.4"], exploit_available=True),
    ],
    "mongodb": [
        CVERecord("CVE-2021-32037", "MongoDB server assertion due to invalid BSON",
                  "high", 7.5, ["<=5.0.3"], cwe="CWE-617"),
        CVERecord("CVE-2019-2389", "MongoDB auth bypass via X.509 client certificate",
                  "high", 7.5, ["<=4.0.9", "<=3.6.13"], cwe="CWE-287"),
        CVERecord("CVE-2016-6494", "MongoDB log injection via query error messages",
                  "medium", 4.7, ["<=3.2.9"], cwe="CWE-117"),
    ],
    "postgresql": [
        CVERecord("CVE-2023-5869", "PostgreSQL buffer overrun in pg_cancel_backend",
                  "high", 8.8, ["<=16.1", "<=15.5", "<=14.10", "<=13.13", "<=12.17"],
                  cwe="CWE-122"),
        CVERecord("CVE-2023-2454", "PostgreSQL row security bypass via extension functions",
                  "high", 7.2, ["<=15.3", "<=14.8", "<=13.11"], cwe="CWE-266"),
        CVERecord("CVE-2019-10164", "PostgreSQL stack-based buffer overflow in SCRAM auth",
                  "critical", 9.8, ["<=11.3", "<=10.8", "<=9.6.13"], cwe="CWE-121"),
        CVERecord("CVE-2018-1058", "PostgreSQL search_path privilege escalation",
                  "high", 8.8, ["<=10.3", "<=9.6.8"], exploit_available=True, cwe="CWE-264"),
    ],
    "elasticsearch": [
        CVERecord("CVE-2021-22145", "Elasticsearch memory disclosure via low-privilege API",
                  "medium", 6.5, ["<=7.13.3"], cwe="CWE-200"),
        CVERecord("CVE-2020-7009", "Elasticsearch XSS in search API",
                  "medium", 6.1, ["<=6.8.7", "<=7.6.1"], cwe="CWE-79"),
        CVERecord("CVE-2015-5377", "Elasticsearch Groovy sandbox escape RCE",
                  "critical", 10.0, ["<1.6.1"], exploit_available=True, cwe="CWE-74"),
        CVERecord("CVE-2014-3120", "Elasticsearch dynamic script RCE (dynamic scripting on)",
                  "critical", 10.0, ["<1.3.8"], exploit_available=True, cwe="CWE-94"),
    ],
    "jenkins": [
        CVERecord("CVE-2024-23897", "Jenkins arbitrary file read via CLI parser",
                  "critical", 9.8, ["<=2.441"], exploit_available=True, cwe="CWE-22"),
        CVERecord("CVE-2023-27898", "Jenkins XSS in update center",
                  "high", 8.8, ["<=2.393"], cwe="CWE-79"),
        CVERecord("CVE-2022-34177", "Jenkins arbitrary file write via tar archive",
                  "critical", 9.1, ["<=2.358"], cwe="CWE-22"),
        CVERecord("CVE-2019-1003000", "Jenkins script security sandbox bypass RCE",
                  "high", 8.8, ["<1.49"], exploit_available=True, cwe="CWE-693"),
        CVERecord("CVE-2018-1000861", "Jenkins Stapler deserialization RCE",
                  "critical", 9.8, ["<=2.153"], exploit_available=True, cwe="CWE-502"),
        CVERecord("CVE-2017-1000353", "Jenkins Java deserialization RCE",
                  "critical", 9.8, ["<=2.56"], exploit_available=True, cwe="CWE-502"),
        CVERecord("CVE-2016-0792", "Jenkins remoting/CLI deserialization RCE",
                  "critical", 10.0, ["<1.650"], exploit_available=True, cwe="CWE-502"),
    ],
    "tomcat": [
        CVERecord("CVE-2025-24813", "Apache Tomcat partial PUT RCE via deserialization",
                  "critical", 9.8, ["<=11.0.2", "<=10.1.34", "<=9.0.98"],
                  exploit_available=True, cwe="CWE-502"),
        CVERecord("CVE-2023-46589", "Apache Tomcat request smuggling via malformed headers",
                  "high", 7.5, ["<=11.0.0-M11", "<=10.1.16", "<=9.0.83", "<=8.5.96"],
                  cwe="CWE-444"),
        CVERecord("CVE-2022-42252", "Apache Tomcat request smuggling via chunked encoding",
                  "high", 7.5, ["<=10.1.1", "<=9.0.68", "<=8.5.82"], cwe="CWE-444"),
        CVERecord("CVE-2020-1938", "Apache Tomcat AJP file read/RCE (Ghostcat)",
                  "critical", 9.8, ["<=9.0.30", "<=8.5.50", "<=7.0.99"],
                  exploit_available=True, cwe="CWE-134"),
        CVERecord("CVE-2019-0232", "Apache Tomcat CGI RCE on Windows",
                  "critical", 9.8, ["9.0.0.M1-9.0.17", "8.5.0-8.5.39", "7.0.0-7.0.93"],
                  exploit_available=True, cwe="CWE-78"),
        CVERecord("CVE-2017-12617", "Apache Tomcat PUT method JSP upload RCE",
                  "critical", 9.8, ["<=8.5.21"], exploit_available=True, cwe="CWE-434"),
        CVERecord("CVE-2016-8735", "Apache Tomcat JMX Connector deserialization RCE",
                  "critical", 9.8, ["<=8.5.8"], exploit_available=True, cwe="CWE-502"),
    ],
    "weblogic_server": [
        CVERecord("CVE-2023-21839", "WebLogic IIOP/T3 unauthorized RCE",
                  "critical", 9.8, ["12.2.1.3.0", "12.2.1.4.0", "14.1.1.0.0"],
                  exploit_available=True, cwe="CWE-502"),
        CVERecord("CVE-2021-2394", "WebLogic IIOP deserialization RCE",
                  "critical", 9.8, ["12.1.3.0.0", "12.2.1.3.0", "12.2.1.4.0", "14.1.1.0.0"],
                  exploit_available=True, cwe="CWE-502"),
        CVERecord("CVE-2020-14882", "WebLogic Console auth bypass RCE",
                  "critical", 9.8, ["10.3.6.0.0", "12.1.3.0.0", "12.2.1.3.0", "12.2.1.4.0"],
                  exploit_available=True, cwe="CWE-287"),
        CVERecord("CVE-2019-2725", "WebLogic deserialization RCE via bea_wls9_async",
                  "critical", 9.8, ["10.3.6.0", "12.1.3.0"], exploit_available=True, cwe="CWE-502"),
    ],
    "apache_struts": [
        CVERecord("CVE-2023-50164", "Apache Struts file upload path traversal RCE",
                  "critical", 9.8, ["<=6.3.0.1", "<=2.5.32"], exploit_available=True, cwe="CWE-22"),
        CVERecord("CVE-2021-31805", "Apache Struts OGNL injection RCE (incomplete CVE-2020-17530 fix)",
                  "critical", 9.8, ["<=2.5.29"], exploit_available=True, cwe="CWE-74"),
        CVERecord("CVE-2020-17530", "Apache Struts forced OGNL evaluation RCE",
                  "critical", 9.8, [">=2.0.0", "<=2.5.25"], exploit_available=True, cwe="CWE-74"),
        CVERecord("CVE-2019-0230", "Apache Struts OGNL injection RCE via tag attributes",
                  "critical", 8.8, [">=2.0.0", "<=2.5.20"], cwe="CWE-74"),
        CVERecord("CVE-2018-11776", "Apache Struts namespace RCE (no-namespace action config)",
                  "critical", 10.0, ["<=2.3.34", "<=2.5.16"], exploit_available=True, cwe="CWE-20"),
        CVERecord("CVE-2017-5638", "Apache Struts Jakarta Content-Type RCE (Equifax breach)",
                  "critical", 10.0, [">=2.3.5", "<=2.3.31", ">=2.5", "<=2.5.10"],
                  exploit_available=True, cwe="CWE-20"),
    ],
    "log4j": [
        CVERecord("CVE-2021-44228", "Log4Shell: Log4j JNDI injection RCE",
                  "critical", 10.0, [">=2.0-beta9", "<=2.14.1"],
                  exploit_available=True, cwe="CWE-917"),
        CVERecord("CVE-2021-45046", "Log4j JNDI injection RCE (CVE-2021-44228 bypass)",
                  "critical", 9.0, ["2.15.0"], exploit_available=True, cwe="CWE-917"),
        CVERecord("CVE-2021-45105", "Log4j infinite recursion DoS via self-referential lookups",
                  "high", 7.5, [">=2.0-alpha1", "<=2.16.0"], cwe="CWE-400"),
        CVERecord("CVE-2021-44832", "Log4j RCE via attacker-controlled JDBC Appender data source",
                  "medium", 6.6, [">=2.0-alpha7", "<=2.17.0"], cwe="CWE-74"),
        CVERecord("CVE-2019-17571", "Log4j 1.x SocketServer deserialization RCE",
                  "critical", 9.8, ["1.x"], exploit_available=True, cwe="CWE-502"),
    ],
    "spring_framework": [
        CVERecord("CVE-2022-22965", "Spring4Shell: Spring MVC RCE via DataBinder",
                  "critical", 9.8, ["<5.3.18", "<5.2.20"], exploit_available=True, cwe="CWE-94"),
        CVERecord("CVE-2022-22963", "Spring Cloud Function SpEL injection RCE",
                  "critical", 9.8, ["<=3.1.6", "<=3.2.2"], exploit_available=True, cwe="CWE-917"),
        CVERecord("CVE-2022-22950", "Spring Framework DoS via SPEL expression",
                  "medium", 6.5, ["<=5.3.16"], cwe="CWE-400"),
        CVERecord("CVE-2021-22060", "Spring Framework log injection",
                  "medium", 4.3, ["<=5.3.13"], cwe="CWE-117"),
        CVERecord("CVE-2018-1270", "Spring Messaging RCE via STOMP broker relay",
                  "critical", 9.8, ["<=5.0.4", "<=4.3.15"], exploit_available=True, cwe="CWE-94"),
    ],
    "apache_shiro": [
        CVERecord("CVE-2023-46750", "Apache Shiro open redirect",
                  "medium", 6.1, ["<2.0.0-alpha-3", "<1.13.0"], cwe="CWE-601"),
        CVERecord("CVE-2023-34478", "Apache Shiro path traversal auth bypass",
                  "critical", 9.8, ["<2.0.0-alpha-3", "<1.12.0"], cwe="CWE-22"),
        CVERecord("CVE-2022-32532", "Apache Shiro authentication bypass via RegExPatternMatcher",
                  "critical", 9.8, ["<1.9.1"], exploit_available=True, cwe="CWE-287"),
        CVERecord("CVE-2020-17523", "Apache Shiro auth bypass via trailing slash",
                  "critical", 9.8, ["<1.7.1"], exploit_available=True, cwe="CWE-287"),
        CVERecord("CVE-2020-11989", "Apache Shiro URL path traversal auth bypass",
                  "critical", 9.8, ["<1.5.3"], exploit_available=True, cwe="CWE-22"),
        CVERecord("CVE-2016-4437", "Apache Shiro RememberMe cookie deserialization RCE",
                  "critical", 9.8, ["<1.2.5"], exploit_available=True, cwe="CWE-502"),
    ],
    "phpmyadmin": [
        CVERecord("CVE-2023-25727", "phpMyAdmin XSS in browse table",
                  "medium", 5.4, ["<5.1.4", ">=5.2.0", "<5.2.1"], cwe="CWE-79"),
        CVERecord("CVE-2021-41182", "phpMyAdmin XSS via drag-and-drop upload",
                  "medium", 6.1, ["<5.1.2"], cwe="CWE-79"),
        CVERecord("CVE-2019-12922", "phpMyAdmin CSRF allows server deletion",
                  "medium", 6.5, ["<4.9.1"], cwe="CWE-352"),
        CVERecord("CVE-2018-19968", "phpMyAdmin local file inclusion via transformation",
                  "medium", 5.4, ["<4.8.4"], cwe="CWE-22"),
        CVERecord("CVE-2016-6619", "phpMyAdmin user information disclosure",
                  "medium", 4.3, ["<4.6.4"], cwe="CWE-200"),
    ],
    "wordpress": [
        CVERecord("CVE-2022-21661", "WordPress SQL injection via WP_Query",
                  "high", 8.8, ["<5.8.3"], exploit_available=True, cwe="CWE-89"),
        CVERecord("CVE-2021-29447", "WordPress XXE via media upload (PHP 8.0)",
                  "high", 7.1, ["<=5.6.1"], exploit_available=True, cwe="CWE-611"),
        CVERecord("CVE-2020-28037", "WordPress XML-RPC auth bypass",
                  "critical", 9.8, ["<=5.5.1"], cwe="CWE-287"),
        CVERecord("CVE-2019-9978", "WordPress Social Warfare RCE via stored XSS",
                  "critical", 9.8, ["<=5.1.0"], exploit_available=True, cwe="CWE-79"),
        CVERecord("CVE-2019-9787", "WordPress CSRF leading to privilege escalation",
                  "high", 8.8, ["<5.1.1"], cwe="CWE-352"),
    ],
    "drupal": [
        CVERecord("CVE-2022-25271", "Drupal improper access in Quick Edit",
                  "high", 8.1, [">=8.x", "<9.3.12", ">=9.4.x", "<9.4.4"], cwe="CWE-284"),
        CVERecord("CVE-2020-13671", "Drupal arbitrary code execution via file extension",
                  "critical", 9.8, ["<9.0.8", "<8.9.9", "<8.8.11"], cwe="CWE-434"),
        CVERecord("CVE-2019-6340", "Drupalgeddon3: REST API RCE",
                  "critical", 9.8, ["8.6.x<8.6.10", "8.5.x<8.5.11"],
                  exploit_available=True, cwe="CWE-502"),
        CVERecord("CVE-2018-7602", "Drupalgeddon2: SA-CORE-2018-004 RCE",
                  "critical", 9.8, ["<7.59", "8.x<8.5.3"], exploit_available=True, cwe="CWE-94"),
        CVERecord("CVE-2018-7600", "Drupalgeddon2: Remote code execution",
                  "critical", 9.8, ["<7.58", "8.x<8.5.1"], exploit_available=True, cwe="CWE-94"),
    ],
    "openssl": [
        CVERecord("CVE-2022-0778", "OpenSSL infinite loop in BN_mod_sqrt() (DoS)",
                  "high", 7.5, ["<3.0.2", "<1.1.1n", "<1.0.2zd"], cwe="CWE-835"),
        CVERecord("CVE-2022-3786", "OpenSSL buffer overrun via X.509 punycode",
                  "high", 7.5, ["3.0.0-3.0.6"], cwe="CWE-121"),
        CVERecord("CVE-2022-3602", "OpenSSL stack buffer overrun in X.509 punycode",
                  "high", 7.5, ["3.0.0-3.0.6"], cwe="CWE-121"),
        CVERecord("CVE-2016-2107", "OpenSSL AES-NI padding oracle (POODLE-variant)",
                  "medium", 5.9, ["<1.0.2h", "<1.0.1t"], exploit_available=True, cwe="CWE-310"),
        CVERecord("CVE-2014-0160", "Heartbleed: OpenSSL memory disclosure",
                  "high", 7.5, ["1.0.1a-1.0.1f"], exploit_available=True, cwe="CWE-126"),
    ],
    "exim": [
        CVERecord("CVE-2023-42115", "Exim auth_spa buffer overflow RCE",
                  "critical", 9.8, ["<4.97"], cwe="CWE-122"),
        CVERecord("CVE-2021-38371", "Exim STARTTLS buffering injection",
                  "medium", 5.9, ["<4.94.2"], cwe="CWE-74"),
        CVERecord("CVE-2020-28018", "Exim TELNETS use-after-free RCE",
                  "critical", 9.8, ["<4.94"], exploit_available=True, cwe="CWE-416"),
        CVERecord("CVE-2020-28017", "Exim receive_add_recipient integer overflow",
                  "critical", 9.8, ["<4.94"], cwe="CWE-190"),
        CVERecord("CVE-2019-15846", "Exim ESTMP heap overflow RCE",
                  "critical", 9.8, ["<4.92.2"], exploit_available=True, cwe="CWE-122"),
        CVERecord("CVE-2019-10149", "Exim RCPT TO remote command execution",
                  "critical", 9.8, ["4.87-4.91"], exploit_available=True, cwe="CWE-78"),
    ],
    "samba": [
        CVERecord("CVE-2007-2447", "Samba username map script command execution (RCE)",
                  "medium", 6.0, ["3.0.0-3.0.25"], exploit_available=True, cwe="CWE-78"),
        CVERecord("CVE-2017-7494", "SambaCry: Samba writable share arbitrary code execution",
                  "critical", 9.8, [">=3.5.0", "<4.6.4"], exploit_available=True, cwe="CWE-749"),
        CVERecord("CVE-2021-44142", "Samba vfs_fruit out-of-bounds heap RW",
                  "critical", 9.9, ["<4.13.17", "<4.14.12", "<4.15.5"],
                  exploit_available=True, cwe="CWE-787"),
        CVERecord("CVE-2022-32744", "Samba forged Kerberos tickets leading to password change",
                  "critical", 8.8, ["<4.16.4", "<4.15.9", "<4.14.14"], cwe="CWE-290"),
        # Zerologon only affects Samba acting as an Active Directory DC, which
        # exists from 4.0; 4.8 flipped the default to a secure schannel, so
        # 4.0–4.7 are the versions vulnerable by default. Bounding it here stops
        # the marker from tagging EVERY Samba (an ancient 3.0.x file server or a
        # patched 4.15 build) with a critical it cannot have — the old
        # "all_with_netlogon" catch-all matched every version.
        CVERecord("CVE-2020-1472", "Zerologon: Netlogon privilege escalation",
                  "critical", 10.0, [">=4.0", "<4.8"], exploit_available=True, cwe="CWE-330"),
    ],
    "dovecot": [
        CVERecord("CVE-2022-30550", "Dovecot auth privilege escalation via SASL",
                  "high", 8.8, ["<2.3.20"], cwe="CWE-269"),
        CVERecord("CVE-2021-33515", "Dovecot STARTTLS response injection",
                  "medium", 5.9, ["<2.3.15"], cwe="CWE-74"),
        CVERecord("CVE-2019-7524", "Dovecot stack buffer overflow in delivery agent",
                  "high", 7.8, ["<2.3.5.2", "<2.2.36.4"], cwe="CWE-121"),
    ],
    "nodejs": [
        CVERecord("CVE-2023-30581", "Node.js main.cjs permission model bypass",
                  "high", 7.5, [">=20.0.0", "<20.3.0"], cwe="CWE-284"),
        CVERecord("CVE-2022-32213", "Node.js HTTP request smuggling via space before colon",
                  "medium", 6.5, ["<18.5.0", "<16.16.0", "<14.20.0"], cwe="CWE-444"),
        CVERecord("CVE-2021-22930", "Node.js use-after-free via HTTP/2 nghttp2",
                  "critical", 9.8, ["<16.6.0", "<14.17.4", "<12.22.4"], cwe="CWE-416"),
        CVERecord("CVE-2019-15605", "Node.js HTTP request smuggling",
                  "critical", 9.8, ["<13.8.0", "<12.15.0", "<10.19.0"], cwe="CWE-444"),
    ],
    "php": [
        CVERecord("CVE-2024-4577", "PHP CGI argument injection RCE on Windows",
                  "critical", 9.8, ["<8.3.8", "<8.2.20", "<8.1.29"],
                  exploit_available=True, cwe="CWE-88"),
        CVERecord("CVE-2023-3824", "PHP heap buffer overflow in phar",
                  "critical", 9.8, ["<8.0.30", "<8.1.22", "<8.2.8"], cwe="CWE-122"),
        CVERecord("CVE-2022-31625", "PHP use-after-free in Postgres extensions",
                  "critical", 9.8, ["<8.1.7", "<8.0.20", "<7.4.30"], cwe="CWE-416"),
        CVERecord("CVE-2021-21707", "PHP special character file injection via SimpleXML",
                  "medium", 5.3, ["<8.0.13", "<7.4.26", "<7.3.33"], cwe="CWE-20"),
        CVERecord("CVE-2019-11043", "PHP-FPM env_path RCE in Nginx configs with PATH_INFO",
                  "critical", 9.8, ["<7.4.0", "<=7.3.10", "<=7.2.23"],
                  exploit_available=True, cwe="CWE-78"),
    ],
    "kubernetes": [
        CVERecord("CVE-2024-9486", "Kubernetes Image Builder default credentials RCE",
                  "critical", 9.8, ["<=0.1.37"], exploit_available=True, cwe="CWE-1392"),
        CVERecord("CVE-2023-5528", "Kubernetes kubelet node RCE via Windows host path",
                  "high", 8.8, ["<1.28.4", "<1.27.8", "<1.26.11"], cwe="CWE-78"),
        CVERecord("CVE-2022-3294", "Kubernetes API server auth bypass via node proxy",
                  "high", 8.8, ["<1.25.4", "<1.24.8", "<1.23.14"], cwe="CWE-285"),
        CVERecord("CVE-2022-3172", "Kubernetes aggregated API server SSRF",
                  "high", 7.1, ["<1.25.2", "<1.24.6"], cwe="CWE-918"),
        CVERecord("CVE-2021-25741", "Kubernetes symlink path traversal via emptyDir/hostPath",
                  "high", 8.8, ["<1.22.2", "<1.21.5", "<1.20.11"], cwe="CWE-61"),
        CVERecord("CVE-2020-8554", "Kubernetes MITM via External LoadBalancer ExternalIP",
                  "medium", 6.3, ["all"], cwe="CWE-269"),
        CVERecord("CVE-2019-11247", "Kubernetes API server allows access to CR API subresources",
                  "high", 8.1, ["<1.13.9", "<1.14.5", "<1.15.2"], cwe="CWE-284"),
    ],
    "docker": [
        CVERecord("CVE-2024-21626", "Docker Leaky Vessels: container escape via runc",
                  "high", 8.6, ["<=1.1.11"], exploit_available=True, cwe="CWE-668"),
        CVERecord("CVE-2022-0492", "Docker container escape via cgroup v1 release_agent",
                  "high", 7.8, ["<20.10.14"], exploit_available=True, cwe="CWE-269"),
        CVERecord("CVE-2021-41091", "Docker file permissions allow execution of arbitrary programs",
                  "medium", 6.3, ["<=20.10.9"], cwe="CWE-732"),
        CVERecord("CVE-2020-15257", "Docker Containerd API UNIX socket privilege escalation",
                  "high", 7.2, ["<1.3.9", "<1.4.3"], exploit_available=True, cwe="CWE-281"),
        CVERecord("CVE-2019-5736", "Docker runc container escape via /proc/self/exe",
                  "high", 8.6, ["<1.0-rc6"], exploit_available=True, cwe="CWE-78"),
    ],
    "vsftpd": [
        CVERecord("CVE-2011-2523", "vsftpd 2.3.4 backdoor command execution",
                  "critical", 10.0, ["2.3.4"], exploit_available=True, cwe="CWE-78"),
    ],
    "proftpd": [
        CVERecord("CVE-2023-48795", "Terrapin attack: prefix truncation in SSH/SFTP",
                  "medium", 5.9, ["<1.3.8b"], cwe="CWE-924"),
        CVERecord("CVE-2020-9273", "ProFTPD memory corruption via mod_copy",
                  "high", 8.8, ["<1.3.7a"], exploit_available=True, cwe="CWE-416"),
        CVERecord("CVE-2019-12815", "ProFTPD arbitrary file copy via mod_copy unauthenticated",
                  "critical", 9.8, ["<1.3.6b"], exploit_available=True, cwe="CWE-284"),
    ],
    "rabbitmq": [
        CVERecord("CVE-2023-46118", "RabbitMQ HTTP API DoS via large HTTP body",
                  "high", 7.7, ["<3.12.6"], cwe="CWE-400"),
        CVERecord("CVE-2021-32718", "RabbitMQ management plugin XSS",
                  "medium", 5.4, ["<3.8.17"], cwe="CWE-79"),
    ],
    "gitlab": [
        CVERecord("CVE-2024-0402", "GitLab arbitrary file write via import",
                  "critical", 9.9, ["<16.5.6", "<16.6.4", "<16.7.2"],
                  exploit_available=True, cwe="CWE-22"),
        CVERecord("CVE-2023-7028", "GitLab account takeover via password reset",
                  "critical", 10.0, [">=16.1.0", "<16.1.6", ">=16.2.0", "<16.2.9",
                                      ">=16.3.0", "<16.3.7", ">=16.5.0", "<16.5.6"],
                  exploit_available=True, cwe="CWE-640"),
        CVERecord("CVE-2022-2185", "GitLab import API RCE via malicious repository",
                  "critical", 9.9, ["<15.1.1", ">=14.0.0", "<=14.10.5"],
                  exploit_available=True, cwe="CWE-94"),
        CVERecord("CVE-2021-22205", "GitLab ExifTool RCE via image upload",
                  "critical", 10.0, [">=11.9.0", "<13.8.8", ">=13.9.0", "<13.9.6",
                                      ">=13.10.0", "<13.10.3"],
                  exploit_available=True, cwe="CWE-20"),
    ],
    "confluence": [
        CVERecord("CVE-2023-22527", "Confluence OGNL injection RCE (SSTI)",
                  "critical", 10.0, ["8.x<8.5.4"], exploit_available=True, cwe="CWE-74"),
        CVERecord("CVE-2022-26134", "Confluence OGNL injection pre-auth RCE",
                  "critical", 10.0, [">=1.3.0", "<7.4.17", ">=7.13.0", "<7.13.7",
                                      ">=7.14.0", "<7.14.3"],
                  exploit_available=True, cwe="CWE-74"),
        CVERecord("CVE-2021-26084", "Confluence WebWork OGNL injection pre-auth RCE",
                  "critical", 9.8, ["<7.4.6"], exploit_available=True, cwe="CWE-74"),
    ],
}

# ── Banner fingerprint patterns for ambiguous services ──

_BANNER_FINGERPRINTS: list[tuple[str, str]] = [
    (r"nginx/?([\d.]+)?",                   "nginx"),
    (r"apache/?([\d.]+)?",                  "apache_http_server"),
    (r"microsoft-iis/?([\d.]+)?",           "microsoft_iis"),
    (r"lighttpd",                            "lighttpd"),
    (r"openresty",                           "openresty"),
    (r"openssh[_-]([\d.p]+)",              "openssh"),
    (r"vsftpd\s+([\d.]+)",                  "vsftpd"),
    (r"proftpd[\s/]+([\d.]+)",              "proftpd"),
    (r"exim\s+([\d.]+)",                    "exim"),
    (r"postfix",                             "postfix"),
    (r"dovecot",                             "dovecot"),
    # nmap reports Samba as "Samba smbd 3.0.20-Debian" / "Samba smbd 4.15.13" —
    # capture the concrete X.Y.Z so old builds (3.0.x) map to their era CVEs and
    # the version-aware matcher excludes the modern ones. Without this the very
    # common Samba banner never resolved to a product at all.
    (r"samba(?:\s+smbd)?\s+(\d+\.\d+(?:\.\w+)?)", "samba"),
    (r"\bsamba\b",                          "samba"),
    (r"mysql",                               "mysql"),
    (r"mariadb",                             "mariadb_server"),
    (r"postgresql\s+([\d.]+)",              "postgresql"),
    (r"redis\s+([\d.]+)",                   "redis"),
    (r"mongodb\s+([\d.]+)",                 "mongodb"),
    (r"elastic",                             "elasticsearch"),
    (r"jenkins",                             "jenkins"),
    (r"apache tomcat/?([\d.]+)?",           "tomcat"),
    (r"weblogic",                            "weblogic_server"),
    (r"jboss",                               "jboss"),
    (r"websphere",                           "websphere"),
    (r"glassfish",                           "glassfish"),
    (r"wordpress",                           "wordpress"),
    (r"drupal",                              "drupal"),
    (r"joomla",                              "joomla"),
    (r"phpmyadmin",                          "phpmyadmin"),
    (r"gitlab",                              "gitlab"),
    (r"confluence",                          "confluence"),
    (r"struts",                              "apache_struts"),
    (r"spring",                              "spring_framework"),
    (r"log4j",                               "log4j"),
    (r"shiro",                               "apache_shiro"),
    (r"rabbitmq",                            "rabbitmq"),
    (r"docker",                              "docker"),
    (r"kubernetes|k8s",                      "kubernetes"),
]


# ── CPE generation ──

@dataclass
class CPEMatch:
    cpe: str
    confidence: float = 1.0
    source: str = ""


def _extract_version_from_banner(banner: str, product: str = "") -> str:
    patterns = []
    if product:
        patterns.append(rf"{re.escape(product)}[/\s]+v?(\d+\.\d+[\.\d\w-]*)")
    patterns += [
        r"(\d+\.\d+\.\d+(?:\.\d+)?(?:[_\-]\w+)?)",
        r"(\d+\.\d+)",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _fingerprint_from_banner(banner: str) -> Optional[tuple[str, str]]:
    """Return (product_key, version) from banner using regex fingerprints."""
    bl = banner.lower()
    for pattern, product_key in _BANNER_FINGERPRINTS:
        m = re.search(pattern, bl)
        if m:
            ver = m.group(1) if m.lastindex and m.group(1) else _extract_version_from_banner(banner)
            return product_key, ver
    return None


def generate_cpe_from_banner(service: str, banner: str, version: str = "") -> list[CPEMatch]:
    """Generate CPE 2.3 strings from service banner with fuzzy matching."""
    matches: list[CPEMatch] = []
    sl = service.lower()

    # Try banner-based fingerprinting first
    fp = _fingerprint_from_banner(banner)
    cpe_entries = CPE_MAP.get(sl, [])

    if fp:
        fp_product, fp_ver = fp
        # Look up CPE entry by product key name
        alt_entries = CPE_MAP.get(fp_product, [])
        if alt_entries:
            cpe_entries = alt_entries
        if not version:
            version = fp_ver

    for vendor, product in cpe_entries:
        ver = version or _extract_version_from_banner(banner, product)
        if ver:
            cpe = f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
            matches.append(CPEMatch(cpe=cpe, confidence=0.9, source="banner"))
        else:
            cpe = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
            matches.append(CPEMatch(cpe=cpe, confidence=0.5, source="service_name"))

    return matches


# ── Version comparison helpers ──

def _parse_ver(v: str) -> tuple[int, ...]:
    """Parse version string into comparable tuple, ignoring non-numeric suffix."""
    parts = re.split(r"[.\-_]", v)
    result = []
    for p in parts[:4]:
        m = re.match(r"(\d+)", p)
        result.append(int(m.group(1)) if m else 0)
    return tuple(result)


def _version_in_range(version: str, spec: str) -> bool:
    """
    Check if version matches a spec string:
      "<=X.Y.Z"       — up to and including
      "<X.Y.Z"        — strictly less than
      ">=X.Y.Z"       — from and including
      ">X.Y.Z"        — strictly greater than
      "X.Y.Z-A.B.C"   — inclusive range
      "X.Y.Z"         — exact match
      "all*"          — always matches
    """
    spec = spec.strip()
    if spec.startswith("all"):
        return True

    try:
        ver_t = _parse_ver(version)
        if "-" in spec and not spec.startswith(("<", ">", "=")):
            lo, hi = spec.split("-", 1)
            return _parse_ver(lo) <= ver_t <= _parse_ver(hi)
        if spec.startswith("<="):
            return ver_t <= _parse_ver(spec[2:])
        if spec.startswith(">="):
            return ver_t >= _parse_ver(spec[2:])
        if spec.startswith("<"):
            return ver_t < _parse_ver(spec[1:])
        if spec.startswith(">"):
            return ver_t > _parse_ver(spec[1:])
        return ver_t == _parse_ver(spec)
    except Exception:
        return False


def _same_branch(version: str, upper_spec: str) -> bool:
    """True when *version* shares the maintained branch of an upper-bound ceiling.

    A per-branch fix ceiling implies a floor at the start of that branch, so a
    version from an *earlier* branch is out of scope: ``<=2.4.39`` means "the 2.4
    line, fixed at 2.4.39", not "every release ever shipped up to 2.4.39", and so
    excludes Apache **2.2.8**.

    The branch's granularity is read from the ceiling's own precision — one level
    coarser than the patch it pins:

    * a 3-part ceiling (``<=5.7.37``, ``<8.3.8``) pins the ``major.minor`` branch
      (MySQL 5.7, PHP 8.3), so ``5.0.51`` / ``5.2.4`` are excluded;
    * a 2-part ceiling (``<=16.1``, where PostgreSQL's minor *is* the patch) pins
      the ``major`` line, so ``15.0`` matches ``<=15.5`` but not ``<=16.1``;
    * a bare 1-part ceiling is too coarse to scope a branch and stays open.
    """
    body = upper_spec.strip().lstrip("<>=").strip()
    parts = [p for p in re.split(r"[.\-_]", body) if p[:1].isdigit()]
    depth = min(len(parts) - 1, 2)
    if depth < 1:
        return True
    return _parse_ver(version)[:depth] == _parse_ver(body)[:depth]


def specs_match_version(version: str, specs: list[str]) -> bool:
    """True when *version* satisfies a CVE record's ``affected_versions`` list.

    A record's spec list is **not** a flat OR. A ``>=``/``>`` lower bound and a
    ``<=``/``<`` upper bound describe a *bounded window* that must hold jointly
    (AND). Treating the list as an OR — the historical behaviour — made a record
    like ``['<=9.7p1', '>=8.5p1']`` (OpenSSH regreSSHion, affected 8.5p1–9.7p1)
    match ANY version ≥ 8.5p1, so a **patched** OpenSSH 9.9 was flagged as
    vulnerable. The same over-match hit every bounded record (Log4Shell on a
    patched 2.17, GitLab/Confluence/Struts above their fixed ceiling, …).

    Semantics, chosen to fix the over-match without ever under-matching relative
    to the old behaviour:

    * standalone clauses — exact versions, ``lo-hi`` dash ranges and ``all*``
      markers — are independent **OR** clauses (a match on any is a match);
    * when the record is bounded on **both** sides, the version must satisfy at
      least one lower bound **AND** at least one upper bound (so a version above
      the top ceiling no longer matches);
    * a record with **multiple** ``<=``/``<`` ceilings and no lower bound lists
      one fix level *per maintained branch* (PHP ``['<8.3.8','<8.2.20','<8.1.29']``
      = the 8.1/8.2/8.3 lines; MySQL ``['<=8.0.28','<=5.7.37']``). Each ceiling
      scopes ONLY its own ``major.minor`` branch, so a version from an earlier,
      unlisted branch (PHP **5.2.4**, MySQL **5.0.51**) is out of scope — matching
      it was a false positive (an ancient install flagged with a modern-branch
      CVE). A single-ceiling one-sided record stays a plain ``<=`` (its branch is
      genuinely ambiguous — e.g. nginx ``['<=1.20.0']`` spans its whole line — so
      flooring it could drop true positives).
    """
    if not specs:
        return False
    lowers = [s for s in specs if s.strip().startswith(">")]
    uppers = [s for s in specs if s.strip().startswith("<")]
    others = [s for s in specs if not s.strip().startswith((">", "<"))]
    # Independent OR clauses first (exact / dash-range / "all*").
    if any(_version_in_range(version, s) for s in others):
        return True
    if lowers and uppers:
        lo_ok = any(_version_in_range(version, s) for s in lowers)
        hi_ok = any(_version_in_range(version, s) for s in uppers)
        return lo_ok and hi_ok
    if uppers and not lowers and len(uppers) > 1:
        # Per-branch fix levels — a version only matches within its own branch.
        return any(_version_in_range(version, s) and _same_branch(version, s)
                   for s in uppers)
    return any(_version_in_range(version, s) for s in lowers + uppers)


# Human-readable product names for the version-undetermined "potential" finding,
# so it reads "Apache HTTP Server" rather than the internal ``apache_http_server``
# key. Any product not listed falls back to a title-cased key.
_PRODUCT_LABELS: dict[str, str] = {
    "apache_http_server": "Apache HTTP Server",
    "microsoft_iis": "Microsoft IIS",
    "mariadb_server": "MariaDB Server",
    "weblogic_server": "Oracle WebLogic Server",
    "apache_struts": "Apache Struts",
    "apache_shiro": "Apache Shiro",
    "spring_framework": "Spring Framework",
    "openssh": "OpenSSH",
    "nginx": "nginx",
    "dovecot": "Dovecot",
    "postgresql": "PostgreSQL",
    "nodejs": "Node.js",
    "phpmyadmin": "phpMyAdmin",
}


# Per-product, one-line "how to confirm the running version" guidance for the
# version-undetermined "potential" finding. The whole reason that finding exists
# is that the banner hid the version, so the honest next step is a *version*
# check — not a claim. ``{host}``/``{port}`` are filled per finding. Any product
# without an entry falls back to a generic service-version re-observation.
_VERSION_CONFIRM_HINTS: dict[str, str] = {
    "apache_http_server":
        "Confirm the exact build: `nmap -sV -p {port} {host}` (many hardened "
        "servers, e.g. Bluehost, strip the version — then use authenticated "
        "`httpd -v` / `apachectl -v`, or the hosting control panel / vendor "
        "advisory). Each CVE below applies ONLY to the affected-version range shown.",
    "nginx":
        "Confirm the exact build: `nmap -sV -p {port} {host}`, or authenticated "
        "`nginx -v`. Each CVE below applies only to the affected-version range shown.",
    "openssh":
        "Re-read the SSH banner: `nc {host} {port}` or `nmap -sV -p {port} {host}`; "
        "distros backport fixes without bumping the banner, so verify the *package* "
        "build (`ssh -V` / `dpkg -l openssh-server`) before treating any CVE as present.",
    "microsoft_iis":
        "Confirm the exact build: `nmap -sV -p {port} {host}` or the `Server:` "
        "header; IIS versions map to Windows releases — verify the OS patch level.",
    "postgresql":
        "Confirm the exact build: `nmap -sV -p {port} {host}` or authenticated "
        "`SELECT version();`. Each CVE below applies only to the range shown.",
    "mysql": "Confirm the exact build: `nmap -sV -p {port} {host}` or `SELECT VERSION();`.",
    "mariadb_server": "Confirm the exact build: `nmap -sV -p {port} {host}` or `SELECT VERSION();`.",
    "dovecot": "Confirm the exact build: `nmap -sV -p {port} {host}` or `dovecot --version`.",
}


def _version_confirm_hint(product_key: str, host: str, port: int) -> str:
    """One honest, product-appropriate line on how to establish the real version
    so the candidate CVEs below can be confirmed or dismissed."""
    tmpl = _VERSION_CONFIRM_HINTS.get(
        product_key,
        "Confirm the exact running version: `nmap -sV -p {port} {host}` to "
        "re-observe the service banner, then match it against each affected-"
        "version range below.")
    p = str(port) if port else ""
    return tmpl.replace("{host}", host or "<host>").replace("{port}", p or "<port>")


def _candidate_details(records: list[CVERecord]) -> list[dict]:
    """Structured, report-ready rows for the version-undetermined finding: one
    per known CVE for the product, richest (highest CVSS) first. Each row names
    the CVE, its published score/severity, the affected-version range it needs,
    CWE, whether a public exploit exists, and an authoritative reference — so the
    reader gets full awareness of the candidate CVEs and *exactly which version
    each requires*, without any of them being asserted as confirmed."""
    rows: list[dict] = []
    for r in sorted(records, key=lambda c: (c.cvss, c.cve_id), reverse=True):
        ref = r.references[0] if r.references else \
            f"https://nvd.nist.gov/vuln/detail/{r.cve_id}"
        rows.append({
            "cve":               r.cve_id,
            "cvss":              round(float(r.cvss), 1),
            "severity":          r.severity,
            "title":             r.title,
            "cwe":               r.cwe or "",
            "affected_versions": ", ".join(r.affected_versions),
            "exploit_available": bool(r.exploit_available),
            "reference":         ref,
        })
    return rows


_CVE_INDEX: dict[str, CVERecord] = {}


def _cve_index() -> dict[str, CVERecord]:
    """Flat ``CVE-id → CVERecord`` view of the inline DB, built once."""
    if not _CVE_INDEX:
        for recs in INLINE_CVE_DB.values():
            for r in recs:
                _CVE_INDEX.setdefault(r.cve_id.upper(), r)
    return _CVE_INDEX


def published_cvss_for(cve_id: Optional[str]) -> Optional[float]:
    """The real published CVSS base score for a CVE in the bundled inline DB,
    or ``None``. Offline and deterministic. Used to backfill the true per-CVE
    score onto a finding that carries a CVE id but lost its numeric score (e.g.
    persisted before per-finding CVSS wiring) so its severity band and CVSS
    column agree on the *real* number rather than a generic class fallback."""
    if not cve_id:
        return None
    rec = _cve_index().get(str(cve_id).strip().upper())
    return rec.cvss if rec and 0.0 < rec.cvss <= 10.0 else None


def lookup_inline_cves(product_key: str, version: str) -> list[CVERecord]:
    """Return CVEs from INLINE_CVE_DB matching product and version.

    With **no version** the full record list is returned as *candidates* — this
    is the accessor ``live_cve_feed.filter_by_version`` relies on to read every
    record's affected ranges, and the accessor the ``map_vulnerabilities``
    version-undetermined path uses to build a single consolidated "potential"
    finding (rather than emitting each as a confirmed CVE). With a version, only
    records whose affected-version window the version genuinely satisfies are
    returned (see :func:`specs_match_version` — bounded ranges match jointly, so
    a patched version above the fixed ceiling no longer over-matches)."""
    records = INLINE_CVE_DB.get(product_key, [])
    if not version:
        return records  # no version → all records as candidates (see docstring)
    return [rec for rec in records
            if specs_match_version(version, rec.affected_versions)]


# ── Zero-day heuristics ──

_DEBUG_PATTERNS: list[tuple[str, str]] = [
    (r"debug|development|dev.?mode",          "Service running in debug/development mode"),
    (r"stack.?trace|traceback|exception",     "Service leaking stack traces"),
    (r"internal server error.*detail",        "Verbose error responses with details"),
    (r"sql.?(error|syntax|exception)",        "Database error messages exposed"),
    (r"php.?(warning|notice|fatal)",          "PHP error messages exposed"),
    (r"connection refused.*127\.",            "Internal service details in error"),
    (r"source.?code|compilation.?error",     "Source code compilation errors exposed"),
    (r"secret[_-]?key\s*[:=]",              "Secret key pattern in banner/response"),
    (r"access.?denied.*password",            "Credential validation details exposed"),
]


def detect_zero_day_indicators(service: str, version: str, banner: str) -> list[dict]:
    """
    Heuristic zero-day detection based on anomalous behavior patterns.
    """
    indicators = []
    banner_lower = banner.lower()

    for pat, desc in _DEBUG_PATTERNS:
        if re.search(pat, banner_lower):
            indicators.append({
                "type": "anomalous_behavior",
                "description": desc,
                "severity": "high",
                "confidence": 0.7,
            })

    # Version-based CVE check using inline DB
    fp = _fingerprint_from_banner(banner)
    product_key = fp[0] if fp else service.lower()
    version_str = (fp[1] if fp else "") or version

    inline_hits = lookup_inline_cves(product_key, version_str)
    for cve_rec in inline_hits:
        indicators.append({
            "type": "known_vulnerable_version",
            "cve_id": cve_rec.cve_id,
            "description": cve_rec.title,
            "severity": cve_rec.severity,
            "cvss": cve_rec.cvss,
            "confidence": 0.9 if version_str else 0.5,
            "exploit_available": cve_rec.exploit_available,
            "cwe": cve_rec.cwe,
        })

    return indicators


# Generic service labels that name a *protocol*, not a *product*. Searching a
# live CVE feed for these pulls unrelated product CVEs onto any host that speaks
# the protocol (the word "http" matches Apache/nginx), so they must never drive a
# dynamic CVE sweep on their own — a concrete product has to be identified first.
_GENERIC_SERVICE_KEYS = frozenset({
    "", "http", "https", "http-proxy", "http-alt", "www", "web", "ssl", "tls",
    "tcp", "udp", "tcpwrapped", "unknown", "service", "socks", "proxy", "rpcbind",
    "netbios-ssn", "microsoft-ds", "domain", "rtsp", "upnp", "soap", "ident",
    "ssl/http", "https-alt",
})


# ── Main mapping entry point ──

async def map_vulnerabilities(host_results: list[dict], nvd_client: Any = None,
                              live_feed: Any = None,
                              max_live_lookups: int = 12) -> list[dict]:
    """Map discovered services to vulnerabilities.

    Layers, most-authoritative first:
      1. **Inline CVE DB** — curated, offline, version-range matched.
      2. **NVD** (if ``nvd_client``) — live CPE lookup.
      3. **Live CVE feed** (if ``live_feed``) — the *dynamic* fallback for the
         "not in my DB" case: when the inline DB has **no** entry for a detected
         product, HEAVEN queries live authoritative feeds (NVD + CIRCL) so a
         brand-new / niche / just-published CVE is still caught. Bounded by
         ``max_live_lookups`` per scan to keep it cheap.
    """
    all_vulns: list[dict] = []
    live_used = 0

    for host in host_results:
        for port_info in host.get("open_ports", []):
            service = port_info.get("service", "")
            banner  = port_info.get("banner", "")
            version = port_info.get("version", "")
            nmap_product = (port_info.get("product") or "").strip()

            # 1. Inline CVE matching. Prefer a banner fingerprint, then nmap's
            #    identified product, and only fall back to the bare service label.
            fp = _fingerprint_from_banner(banner)
            if fp:
                product_key = fp[0]
            elif nmap_product:
                product_key = nmap_product.lower()
            else:
                product_key = service.lower()
            version_str  = (fp[1] if fp else "") or version

            inline_cves = lookup_inline_cves(product_key, version_str)

            # 3a. Dynamic fallback — fire when the inline DB produced NO
            #     version-matched CVE for this service. That covers two cases:
            #       (a) the product is entirely unknown to the inline DB, and
            #       (b) the product IS known but the observed version falls
            #           outside every inline CVE's affected range — e.g. an
            #           ancient Samba 3.0.20 against a DB that only carries the
            #           modern SambaCry/Zerologon entries. Gating on the product
            #           key alone silently dropped case (b): a decade-old service
            #           got neither an inline hit nor a live lookup, so its
            #           era-appropriate CVE (CVE-2007-2447 for Samba 3.0.20,
            #           CVE-2010-2075 for UnrealIRCd 3.2.8.1, …) was never found.
            #     Still requires a concrete PRODUCT, not a bare protocol: a
            #     generic label ("http", "https", "www", "ssl", …) must NOT drive
            #     a live NVD sweep — searching the feed for the word "http" pulls
            #     every Apache/nginx CVE onto any HTTP server (a plain Python
            #     http.server was landing ~25 false "Apache" CVEs). When the
            #     product IS in the inline DB and DID match, inline stays
            #     authoritative and the feed is skipped (no double-reporting).
            if (live_feed is not None and not inline_cves
                    and live_used < max_live_lookups
                    and product_key not in _GENERIC_SERVICE_KEYS
                    and (service or banner)):
                live_used += 1
                try:
                    # Pass the RESOLVED product_key, not the raw service label:
                    # the feed maps a bare "http" to Apache via its CPE map, which
                    # is exactly how a Python http.server was collecting Apache
                    # CVEs. We already fingerprinted the product above, so hand the
                    # feed that (and skip the banner to avoid a re-fingerprint).
                    live_hits = await live_feed.discover_for_service(
                        product_key, "", version_str)
                    host_name = host.get("host", "unknown")
                    # A live hit is only asserted as a distinct finding when the
                    # feed actually matched an affected-version RANGE
                    # (``version_confirmed``). A bare keyword/product-name match
                    # with no confirmed version is FP-prone: many public CVEs share
                    # a product WORD but describe a different implementation or
                    # platform — the word "vnc" pulls RealVNC-on-Windows onto a
                    # Linux VNC, "telnet" pulls GNU-inetutils onto netkit telnetd.
                    # So emit confirmed hits individually and collapse the
                    # unconfirmed remainder into ONE honest low "potential" finding
                    # (mirroring the version-less inline path) instead of asserting
                    # specific, possibly misattributed, CVEs.
                    confirmed = [lc for lc in live_hits if lc.version_confirmed]
                    unconfirmed = [lc for lc in live_hits if not lc.version_confirmed]
                    for lc in confirmed:
                        lc_score, lc_sev = _score_and_severity(lc.cvss, lc.severity)
                        all_vulns.append({
                            "host": host_name,
                            "port": port_info.get("port", 0),
                            # vuln_type drives report taxonomy — "vulnerable_service"
                            # aliases to the "vulnerable_component" KB entry so a
                            # dynamically-discovered CVE never lands uncategorised.
                            "vuln_type": "vulnerable_service",
                            "cve": lc.cve_id, "title": lc.title,
                            # cvss_base is the canonical per-finding score the ML
                            # scorer + report resolver read; severity follows it.
                            "severity": lc_sev, "cvss": lc.cvss,
                            "cvss_base": lc_score,
                            "cvss_vector": lc.cvss_vector,
                            "cwe": lc.cwe, "product": product_key,
                            "version": version_str,
                            "in_kev": lc.in_kev,
                            "version_confirmed": lc.version_confirmed,
                            "epss": lc.epss,
                            "exploit_available": lc.exploit_available,
                            "exploit_url": lc.exploit_url,
                            "source": f"live:{lc.source}",
                            "confidence": 0.85,
                        })
                    if unconfirmed:
                        label = _PRODUCT_LABELS.get(
                            product_key, product_key.replace("_", " ").title())
                        cand = sorted({lc.cve_id for lc in unconfirmed})
                        examples = [lc.cve_id for lc in sorted(
                            unconfirmed, key=lambda x: x.cvss, reverse=True)[:6]]
                        all_vulns.append({
                            "host": host_name,
                            "port": port_info.get("port", 0),
                            "target": host_name,
                            "vuln_type": "potential_vulnerable_service",
                            "title": f"Potential vulnerable service: {label} "
                                     f"(version unconfirmed)",
                            "severity": "low",
                            "description": (
                                f"{label} was identified on this host but a running "
                                f"version could not be confirmed against any CVE's "
                                f"affected range, so applicability cannot be established "
                                f"from the outside. {len(cand)} CVEs name this product "
                                f"in public feeds (e.g. {', '.join(examples)}). These "
                                f"are UNVERIFIED candidates — a public CVE for a product "
                                f"name may refer to a different implementation or "
                                f"platform — confirm the exact product and version "
                                f"before treating any as present."
                            ),
                            "product": product_key,
                            "version": version_str or "undetermined",
                            "confidence": 0.3,
                            "source": f"live:{unconfirmed[0].source}",
                            "evidence": {
                                "product": label,
                                "version": version_str or "undetermined",
                                "candidate_cve_count": len(cand),
                                "candidate_cves": cand,
                                "verification": (
                                    "Unauthenticated product-name matching cannot "
                                    "confirm these CVEs are present; confirm the exact "
                                    "product/version via an authenticated check."
                                ),
                            },
                        })
                except Exception as e:
                    logger.debug("live CVE feed error for %s: %s", product_key, e)

            if version_str:
                # A real version was observed → emit each matched CVE as its own
                # finding with the genuine per-CVE score. These are true version
                # matches (the window matcher already excluded patched versions).
                for cve_rec in inline_cves:
                    rec_score, rec_sev = _score_and_severity(cve_rec.cvss, cve_rec.severity)
                    all_vulns.append({
                        "host":             host.get("host", "unknown"),
                        "port":             port_info.get("port", 0),
                        # vuln_type drives report taxonomy — without it the finding
                        # persists as "unknown". "vulnerable_service" aliases to the
                        # "vulnerable_component" KB entry so an inline-DB CVE is
                        # categorised the same as a live/NVD one.
                        "vuln_type":        "vulnerable_service",
                        "cve":              cve_rec.cve_id,
                        "title":            cve_rec.title,
                        # Severity follows the objective CVSS band; cvss_base carries
                        # the real per-CVE score end-to-end (ML + report resolver).
                        "severity":         rec_sev,
                        "cvss":             cve_rec.cvss,
                        "cvss_base":        rec_score,
                        "cwe":              cve_rec.cwe,
                        "product":          product_key,
                        "version":          version_str,
                        "exploit_available": cve_rec.exploit_available,
                        "source":           "inline_db",
                        "confidence":       0.9,
                    })
            elif inline_cves:
                # No version could be read from the banner. Emitting every product
                # CVE as a confirmed Critical/High/Open is the classic "outside-in"
                # false positive: a *patched* host that still advertises a bare
                # product name (e.g. Bluehost's "Server: Apache", no version) would
                # light up red with a dozen CVEs it isn't actually vulnerable to,
                # and distributions routinely backport fixes without bumping the
                # banner. Collapse to ONE honest, low-severity POTENTIAL finding
                # that names the candidate CVEs for manual verification instead of
                # N speculative Criticals. `potential_vulnerable_service` is an
                # "unconfirmed" type, so reconcile_severity caps its score to the
                # low band and it never inflates the Critical/High count.
                host_name = host.get("host", "unknown")
                label = _PRODUCT_LABELS.get(
                    product_key, product_key.replace("_", " ").title())
                candidates = sorted({c.cve_id for c in inline_cves})
                worst = max((c.cvss for c in inline_cves), default=0.0)
                examples = [c.cve_id for c in
                            sorted(inline_cves, key=lambda c: c.cvss, reverse=True)[:6]]
                all_vulns.append({
                    "host":       host_name,
                    "port":       port_info.get("port", 0),
                    # A bare host target (no :port) so the same version-less service
                    # seen on several ports collapses to one host-level finding.
                    "target":     host_name,
                    "vuln_type":  "potential_vulnerable_service",
                    "title":      f"Potential vulnerable service: {label} "
                                  f"(version undetermined)",
                    "severity":   "low",
                    "description": (
                        f"{label} was identified on this host but its exact version "
                        f"could not be confirmed from the banner, so CVE applicability "
                        f"cannot be established from the outside. {len(candidates)} "
                        f"CVEs are known for this product "
                        f"(e.g. {', '.join(examples)}). These are UNVERIFIED "
                        f"candidates — confirm the running version via an "
                        f"authenticated check or vendor advisory before treating any "
                        f"as present. Distributions frequently backport security "
                        f"fixes while leaving the banner version unchanged."
                    ),
                    "product":    product_key,
                    "confidence": 0.3,
                    "source":     "inline_db",
                    "evidence": {
                        "product": label,
                        "version": "undetermined",
                        "candidate_cve_count": len(candidates),
                        "candidate_cves": candidates,
                        # Full per-CVE awareness (id, published score/severity, the
                        # affected-version range each REQUIRES, CWE, exploit flag,
                        # reference) so the reader sees exactly what this service
                        # *might* be vulnerable to — without any CVE being asserted
                        # as confirmed. Rendered as a table in report + UI.
                        "candidate_details": _candidate_details(inline_cves),
                        "highest_candidate_cvss": worst,
                        "how_to_confirm": _version_confirm_hint(
                            product_key, host_name, port_info.get("port", 0)),
                        "verification": (
                            "Confirm the exact version (authenticated access or "
                            "vendor advisory); unauthenticated banner matching "
                            "cannot confirm these CVEs are present."
                        ),
                    },
                })

            # 2. Generate CPEs for NVD lookup
            cpe_matches = generate_cpe_from_banner(service, banner, version)
            if nvd_client:
                for cpe_match in cpe_matches:
                    try:
                        cves = await nvd_client.search_by_cpe(cpe_match.cpe)
                        for cve in cves:
                            nvd_score, nvd_sev = _score_and_severity(
                                cve.cvss_base, cve.severity)
                            all_vulns.append({
                                "host":             host.get("host", "unknown"),
                                "port":             port_info.get("port", 0),
                                # Same taxonomy as the inline/live paths so an
                                # NVD-sourced CVE never persists as "unknown".
                                "vuln_type":        "vulnerable_service",
                                "cve":              cve.cve_id,
                                "title":            cve.title,
                                "severity":         nvd_sev,
                                "cvss":             cve.cvss_base,
                                "cvss_base":        nvd_score,
                                "cpe":              cpe_match.cpe,
                                "cpe_confidence":   cpe_match.confidence,
                                "source":           "nvd",
                            })
                    except Exception as e:
                        logger.debug(f"NVD lookup error for {cpe_match.cpe}: {e}")

            # 3. Zero-day heuristics
            for ind in detect_zero_day_indicators(service, version, banner):
                if ind.get("type") == "known_vulnerable_version":
                    # already captured by inline_cves pass
                    continue
                all_vulns.append({
                    "host":       host.get("host", "unknown"),
                    "port":       port_info.get("port", 0),
                    "cve":        "HEAVEN-HEURISTIC",
                    "title":      ind["description"],
                    "severity":   ind["severity"],
                    "cvss":       0.0,
                    "type":       "zero_day_heuristic",
                    "confidence": ind["confidence"],
                    "source":     "heuristic",
                })

    # 4. Passively-observed CVEs from public internet-scan data (Shodan
    #    InternetDB, merged into the host dict during recon). These are CVE IDs
    #    the public record already ties to the host's internet-facing exposure —
    #    surfaced so a vulnerability that is present on the target but absent from
    #    our inline DB is never missed. They are UNVALIDATED from our vantage, so
    #    they carry source="passive:internetdb" + low confidence; the
    #    confirmation_status resolver keeps them "Potential" and they never inflate
    #    the confirmed-only Overall Risk. Deduped against any CVE already found
    #    actively on the same host.
    _active_cves_by_host: dict[str, set[str]] = {}
    for v in all_vulns:
        cid = str(v.get("cve") or "").upper()
        if cid.startswith("CVE-"):
            _active_cves_by_host.setdefault(str(v.get("host") or ""), set()).add(cid)

    for host in host_results:
        host_name = host.get("host", "unknown")
        seen_here = _active_cves_by_host.setdefault(host_name, set())
        for cve_id in host.get("passive_cves", []) or []:
            cid = str(cve_id).upper()
            if not cid.startswith("CVE-") or cid in seen_here:
                continue
            seen_here.add(cid)
            pub = published_cvss_for(cid)
            score, sev = _score_and_severity(pub or 0.0, "medium")
            all_vulns.append({
                "host":        host_name,
                "target":      host_name,
                "port":        0,
                "vuln_type":   "vulnerable_service",
                "cve":         cid,
                "title":       f"Publicly-reported vulnerability {cid}",
                "severity":    sev,
                "cvss":        pub or 0.0,
                "cvss_base":   score,
                "source":      "passive:internetdb",
                "confidence":  0.5,
                "description": (
                    f"Shodan's public InternetDB associates {cid} with this host's "
                    "internet-facing exposure. This is passive OSINT, UNVERIFIED "
                    "from the scan origin — confirm the affected component and "
                    "version (authenticated check or active exploitation) before "
                    "treating it as exploitable."
                ),
                "evidence": {"source_feed": "shodan_internetdb",
                             "validation": "passive-osint-unconfirmed"},
            })

    # Attribute every CVE finding to the concrete host:port it came from. The
    # persistence layer synthesises target=host, but the raw findings (rendered
    # in the CLI end-of-scan table, the web progress feed and the kill chain)
    # otherwise showed a blank Target for a CRITICAL CVE — which reads as broken.
    # Use host:port when a real port is known, else the bare host.
    for v in all_vulns:
        if v.get("target"):
            continue
        host_str = str(v.get("host") or "").strip()
        if not host_str:
            continue
        port_num = v.get("port") or 0
        v["target"] = f"{host_str}:{port_num}" if port_num else host_str

    # Deduplicate. A confirmed CVE is identified per (host, port, cve) so
    # distinct CVEs — and the same CVE on genuinely different service ports —
    # stay distinct. The consolidated version-undetermined "potential" finding is
    # a property of the product on the host, so it collapses per (host, product):
    # a service whose version is hidden but is reachable on several ports (Apache
    # on 80 AND 443) is reported once, not once per port.
    seen: set[tuple] = set()
    unique: list[dict] = []
    for v in all_vulns:
        if v.get("vuln_type") == "potential_vulnerable_service":
            key = ("__potential__", v.get("host"), v.get("product"))
        else:
            key = (v.get("host"), v.get("port"), v.get("cve"))
        if key not in seen:
            seen.add(key)
            unique.append(v)

    logger.info(f"CVE mapping complete: {len(unique)} vulnerabilities across {len(host_results)} hosts")
    return unique
