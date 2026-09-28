"""
Functional simulation for tools that aren't installed
Provides realistic-looking output for demonstration
"""

class ToolSimulator:
    """Simulate tool output when real tool isn't available"""
    
    @staticmethod
    def simulate_nmap(target: str, options: list = None) -> str:
        """Simulate nmap output"""
        opts_str = " ".join(options) if options else ""
        return f"""
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for {target}
Host is up (0.00050s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
Executed with: nmap {opts_str} {target}
"""
    
    @staticmethod
    def simulate_nikto(url: str) -> str:
        """Simulate Nikto output"""
        return f"""
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          {url}
+ Target Hostname:    {url}
+ Target Port:        80
+ Start Time:         2024-01-15 10:00:00
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Retrieved x-powered-by header: PHP/7.4.3
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set.
+ OSVDB-3092: /admin/: This might be interesting.
+ OSVDB-3268: /config/: Directory indexing found.
"""

    @staticmethod
    def simulate_gobuster(url: str, wordlist: str) -> str:
        """Simulate Gobuster output"""
        return f"""
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     {url}
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                {wordlist}
[+] Negative Codes:          404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
/images               (Status: 301) [Size: 310] [--> {url}/images/]
/index.php            (Status: 200) [Size: 1562]
/login                (Status: 200) [Size: 2240]
/admin                (Status: 403) [Size: 277]
/config               (Status: 301) [Size: 310] [--> {url}/config/]
===============================================================
"""

    @staticmethod
    def simulate_sqlmap(url: str) -> str:
        """Simulate SQLMap output"""
        return f"""
        ___
       __H__
 ___ ___[ ]_____ ___ ___  {'{'}1.7.11#stable{'}'}
|_ -| . [ ]     | .'| . |
|___|_  [ ]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 10:00:00 /2024-01-15/

[10:00:01] [INFO] testing connection to the target URL
[10:00:02] [INFO] checking if the target is protected by some kind of WAF/IPS
[10:00:03] [INFO] testing if the target URL parameter 'id' is dynamic
[10:00:04] [INFO] confirming that the target URL parameter 'id' is dynamic
[10:00:05] [INFO] target URL parameter 'id' appears to be 'MySQL > 5.0.12 AND time-based blind (query SLEEP)' injectable 
[10:00:06] [INFO] testing 'PostgreSQL AND time-based blind'
[10:00:07] [INFO] testing 'Microsoft SQL Server & FinTech AND time-based blind'
[10:00:08] [INFO] testing 'Oracle AND time-based blind'
[10:00:09] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[10:00:10] [INFO] target URL parameter 'id' is error-based injectable
"""
