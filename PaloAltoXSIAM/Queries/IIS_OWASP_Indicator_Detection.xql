"""
Parses raw IIS W3C log lines from iis_iis_raw into normalized fields (timestamp, source IP, destination IP/port, username, HTTP method, URI, status, user-agent, referer, and time-taken). Excludes common error/redirect status codes (404/400/302/403/408/409/500/308/405) 
to focus on successful/meaningful web activity. Supports detection of OWASP-style indicators (e.g., Injection, Broken Access Control, and scanner/exploit user-agents) by applying regex filters to the URI and User-Agent fields."
"""


config case_sensitive = false |
dataset = iis_iis_raw 
| alter 
    iis_date = arrayindex(regextract(_raw_log, "^(\d{4}-\d{2}-\d{2})"), 0), //
    iis_time = arrayindex(regextract(_raw_log, "^\d{4}-\d{2}-\d{2}\s+(\d{2}:\d{2}:\d{2})"), 0),
    src_ip   = arrayindex(regextract(_raw_log, "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    method   = arrayindex(regextract(_raw_log, "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+(\S+)"), 0),
    uri      = arrayindex(regextract(_raw_log, "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+(\S+)"), 0),
    dst_port = arrayindex(regextract(_raw_log, "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\S+\s+(\d+)"), 0),
    username = arrayindex(regextract(_raw_log, "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\S+\s+\d+\s+(\S+)"), 0),
    dst_ip   = arrayindex(regextract(_raw_log, "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\S+\s+\d+\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    time_taken_ms = arrayindex(regextract(_raw_log, "(\d+)\s*$"), 0),
    referer = arrayindex(regextract(_raw_log, "\s(https?://\S+|-)\s+\d{3}\s+\d+\s+\d+\s+\d+\s*$"), 0),
    user_agent = arrayindex(regextract(_raw_log, "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d{1,3}(?:\.\d{1,3}){3}\s+(\S+)"), 0),
    status = arrayindex(regextract(_raw_log , "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+(?:\s+\S+)?\s+(\d{3})\s+\d+\s+\d+\s+\d+\s*$"),0)
| fields _time, iis_date, iis_time, src_ip, dst_ip, dst_port, username, method, uri, status, time_taken_ms, _raw_log, referer, user_agent
| filter status not in("404","400", "302","403","408","409","500", "308", "405")

//////---A03: Injection (SQLi / command injection)---//////
//| filter uri ~=  "(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bwaitfor\b|\bsleep\b|\bbenchmark\b)" //or 
//| filter uri ~=  "(\b(?:cmd=|exec=|powershell|/bin/sh|/bin/bash|wget|curl|nc|netcat)\b)"
//| filter uri ~=  "(--|/\*|\*/|;|%3b|%27|%22)"
| filter uri contains "robots.txt"

//////---A01: Broken Access Control (forced browsing / traversal)---//////
//| filter uri ~=  "(\.\./|%2e%2e%2f|%2e%2e\\|%2e%2e%5c)"
//| filter uri ~=  "(/admin\b|/administrator\b|/manage\b|/console\b|/wp-admin\b|/phpmyadmin\b)"
//| filter uri ~=  "(/\.git\b|/\.env\b|/web\.config\b|/appsettings\.json\b|/id_rsa\b)"


///----A06: Vulnerable/Outdated Components (scanner + exploit attempts)
//| filter user_agent ~=  "(nikto|sqlmap|acunetix|nessus|nuclei|w3af|zap|owasp|burp|dirbuster|gobuster|ffuf|masscan|zgrab|whatweb|nmap)"
//| filter user_agent ~=  "(/wp-content/|/wp-includes/|/xmlrpc\.php|/vendor/phpunit|/\.well-known/)"

//---Testing
//| filter uri ~= "(<script|%3cscript|onerror=|onload=|alert\(|document\.cookie|%3cimg|javascript:)"
| sort desc _time
