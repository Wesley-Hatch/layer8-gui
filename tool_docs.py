"""
Per-tool use-case documentation for the Layer8 GUI.

Each entry answers, for one tool: what it's for (purpose), WHEN you'd reach for
it, HOW to drive it in this app, what it can actually do (capabilities), and the
caveats/cautions that matter. The GUI's "Use Case" panel renders these.

Keys match the tool names passed to show_tool_screen()/show_ddos_screen().
"""

from __future__ import annotations

from typing import Dict


# A universal reminder appended to every tool's caveats by the renderer.
GLOBAL_CAVEAT = (
    "Only use against systems you own or have explicit, written authorization to "
    "test. Unauthorized scanning or attack may be illegal."
)

TOOL_DOCS: Dict[str, dict] = {
    # ----------------------------- Network -----------------------------
    "Nmap/Nessus": {
        "tagline": "Map hosts, ports, services and known vulnerabilities.",
        "purpose": "Discover live hosts, open ports, the services/versions behind them, "
                   "and flag known vulnerabilities - the industry-standard first look at a target.",
        "when": "At the very start of an assessment, to map the attack surface of a host or "
                "subnet before deciding where to dig deeper.",
        "how": "Enter an IP, hostname, or CIDR (e.g. 192.168.1.0/24). Pick an intensity: low = "
               "slow and stealthy, high = fast and aggressive. Run, then read the open ports / "
               "service versions in the results.",
        "capabilities": [
            "Host discovery and TCP/UDP port scanning",
            "Service and version detection (what's actually running on each port)",
            "Scripted vulnerability checks and basic OS fingerprinting",
        ],
        "caveats": [
            "Requires nmap installed on this machine.",
            "Aggressive intensities are loud and will show up in IDS/IPS and logs.",
            "Version/OS detection is a best-guess, not proof; confirm before acting.",
        ],
    },
    "Port Scan": {
        "tagline": "Lightweight built-in check for open TCP ports on one host.",
        "purpose": "Quickly see which TCP ports are open on a single machine without needing "
                   "external tools.",
        "when": "Fast triage of one host's exposed services, or when nmap isn't installed.",
        "how": "Enter a target IP/hostname (or tick 'Scan own machine' for localhost) and run. "
               "It opens socket connections to common ports and lists the ones that answer.",
        "capabilities": [
            "TCP connect scan of common ports",
            "Basic service-name mapping per open port",
        ],
        "caveats": [
            "TCP connect scans are fully logged by the target.",
            "No UDP, no version detection, slower and less capable than nmap.",
        ],
    },
    "Ping Sweep": {
        "tagline": "Find which hosts on a network are alive.",
        "purpose": "Enumerate live hosts across an IP range so you know what's actually out there.",
        "when": "Inventory a subnet before deeper scanning, or confirm which machines are online.",
        "how": "Enter a range/CIDR (e.g. 10.0.0.0/24) and run. Responding hosts are listed, with "
               "MAC/vendor where discoverable.",
        "capabilities": [
            "ICMP/ARP liveness discovery across a range",
            "MAC address and vendor lookup on the local segment",
        ],
        "caveats": [
            "Hosts that block ping will look 'down' even when up.",
            "ARP-based discovery only works on your own local network segment.",
        ],
    },
    "Firewall Audit": {
        "tagline": "Review firewall state and spot weak/permissive rules.",
        "purpose": "Identify host-firewall misconfigurations, overly broad allow rules, and "
                   "potential bypasses.",
        "when": "Assessing a machine's host-based firewall posture - most useful on the box itself.",
        "how": "Tick 'Scan own machine' (recommended) or enter a target, choose the audit type, "
               "and run.",
        "capabilities": [
            "Enumerate firewall profiles/state and rules",
            "Flag permissive or risky rule configurations",
        ],
        "caveats": [
            "Remote firewall inspection is limited; results are most accurate locally.",
            "For deep Windows firewall + hardening review, use the win_audit package.",
        ],
    },
    "Traffic Monitor": {
        "tagline": "Capture live traffic for a set time and export it.",
        "purpose": "Watch what a host is actually communicating with over a fixed duration, and "
                   "export the session to Excel for review.",
        "when": "Investigating suspicious connections, documenting what a device talks to, or "
                "baselining normal traffic.",
        "how": "Set a duration, run, and let it capture; export to Excel when done.",
        "capabilities": [
            "Live packet capture with website / TLS SNI detection",
            "Excel export of the captured session",
        ],
        "caveats": [
            "Needs a capture driver (Npcap on Windows, libpcap on Linux) and usually admin/root.",
            "Only sees traffic on the capturing interface; encrypted payloads aren't decoded.",
        ],
    },
    "WiFi Traffic Analyzer": {
        "tagline": "Enumerate Wi-Fi networks and devices on your LAN.",
        "purpose": "Scan nearby wireless networks and identify devices (and associated user/device "
                   "type) on the network you're connected to.",
        "when": "Wireless-environment recon, or mapping who/what is on the local network.",
        "how": "Run it (no target needed). Review the discovered SSIDs and connected devices.",
        "capabilities": [
            "Nearby SSID enumeration",
            "Connected-device identification on the current network",
        ],
        "caveats": [
            "Requires a wireless adapter; advanced features are platform-dependent.",
            "Only analyzes the network you're currently attached to.",
        ],
    },
    "Security Camera Finder": {
        "tagline": "Locate IP cameras and identify their make/model.",
        "purpose": "Find networked security cameras and fingerprint their vendor/model - useful "
                   "for spotting unsecured or forgotten devices.",
        "when": "Physical-security asset inventory, or hunting for exposed camera feeds on a LAN.",
        "how": "Run it to scan the local network and list discovered cameras.",
        "capabilities": [
            "Camera IP discovery on the network",
            "Vendor/model fingerprinting",
        ],
        "caveats": [
            "Fingerprinting is heuristic and can be wrong.",
            "Only finds cameras reachable from this network.",
        ],
    },
    "Sniffer": {
        "tagline": "Passively capture packets on the interface.",
        "purpose": "Listen to raw network traffic passing your interface for low-level inspection.",
        "when": "Troubleshooting or inspecting protocols on a segment you're authorized to monitor.",
        "how": "Run it and observe the captured packet summaries.",
        "capabilities": [
            "Live packet capture and summary of traffic on the local segment",
        ],
        "caveats": [
            "Needs admin/root plus a capture driver.",
            "Only sees local-segment or mirrored traffic; capturing others' traffic is sensitive - "
            "do it only where authorized.",
        ],
    },
    "Wireshark": {
        "tagline": "Launch full Wireshark for deep packet analysis.",
        "purpose": "Open the full Wireshark application for detailed, manual protocol dissection.",
        "when": "You need more than the built-in sniffer - stream reconstruction, deep filters, "
                "per-field decoding.",
        "how": "Launches Wireshark (optionally filtered to your target host); analyze there.",
        "capabilities": [
            "Full protocol decoding, display filters, follow-stream, expert analysis",
        ],
        "caveats": [
            "Wireshark must be installed separately.",
            "It's an external app; live capture still needs capture privileges.",
        ],
    },

    # ----------------------------- Web Scan -----------------------------
    "Nikto-Lite": {
        "tagline": "Scan a web server for risky files and misconfigurations.",
        "purpose": "Check a web server for dangerous files/CGIs, outdated software, and common "
                   "misconfigurations.",
        "when": "Early assessment of a website/web server you're authorized to test.",
        "how": "Enter the site URL or host and run; review flagged items.",
        "capabilities": [
            "Checks for known risky files/paths, server banners, and common issues",
        ],
        "caveats": [
            "Very noisy and fully logged by the server.",
            "Many results are informational; it is not a full web-app pentest.",
        ],
    },
    "DirBrute": {
        "tagline": "Discover hidden directories/files by guessing.",
        "purpose": "Brute-force directory and file names to find unlinked/hidden content on a web "
                   "server.",
        "when": "Content-discovery phase of a web assessment on an authorized target.",
        "how": "Enter the base URL, pick a brute/wordlist type, and run.",
        "capabilities": [
            "Wordlist-driven path enumeration with status-code filtering",
        ],
        "caveats": [
            "Generates a large volume of requests - noisy and may trip WAF/rate limits.",
            "Only as good as the wordlist; misses truly unguessable paths.",
        ],
    },
    "Burp Suite": {
        "tagline": "Launch Burp to intercept and manipulate web traffic.",
        "purpose": "Open Burp Suite for hands-on interception and modification of web requests.",
        "when": "Manual web-app testing - auth flows, parameters, APIs, session handling.",
        "how": "Launches Burp; point your browser's proxy at it and drive requests through.",
        "capabilities": [
            "Intercepting proxy, request repeater, and scanning (Pro edition)",
        ],
        "caveats": [
            "External tool with a learning curve; requires browser proxy configuration.",
        ],
    },

    # ----------------------------- Vuln Scan -----------------------------
    "CVE Search": {
        "tagline": "Fingerprint services/versions so you can look up their CVEs.",
        "purpose": "Identify the services and version banners running on a target - the real "
                   "prerequisite for finding known vulnerabilities (CVEs).",
        "when": "Early assessment, to learn exactly what software/versions a host exposes.",
        "how": "Enter the target and run. It port-scans and grabs each service's banner / HTTP "
               "Server header, then lists the product/version strings. Look those up at "
               "https://nvd.nist.gov/vuln/search (or run the Nmap tool with -sV/--script vuln).",
        "capabilities": [
            "Real, fully offline service + version fingerprinting (no external API)",
            "Reads HTTP(S) Server/X-Powered-By headers and raw service banners (SSH/FTP/SMTP/…)",
        ],
        "caveats": [
            "It does not query a CVE database itself - you match the versions against NVD.",
            "Banners can be hidden or spoofed; absence of a banner isn't proof of safety.",
        ],
    },
    "WPScan-Lite": {
        "tagline": "Enumerate WordPress version, plugins, themes and users.",
        "purpose": "Fingerprint a WordPress site and enumerate plugins/themes/users and known vulns.",
        "when": "The target is a WordPress site you're authorized to test.",
        "how": "Enter the site URL and run.",
        "capabilities": [
            "WordPress version detection, plugin/theme/user enumeration",
        ],
        "caveats": [
            "WordPress-only and noisy.",
            "Some vulnerability data needs an API token to populate.",
        ],
    },

    # ----------------------------- System -----------------------------
    "Win Audit": {
        "tagline": "Quick Windows security-settings check (baseline).",
        "purpose": "Check core Windows posture - OS info, admin accounts, listening ports, patches.",
        "when": "A fast local sanity check of a Windows machine's configuration.",
        "how": "Run on the local machine (no target needed).",
        "capabilities": [
            "Reports OS info, local administrators, listening ports, installed hotfixes",
        ],
        "caveats": [
            "This is the BASELINE check. For adversary-grade Windows auditing (67 checks incl. "
            "privilege-escalation, credential access, coercion/relay, persistence and Active "
            "Directory), use the win_audit package (python -m win_audit).",
            "Run elevated for full coverage.",
        ],
    },
    "LinPeas": {
        "tagline": "Enumerate Linux privilege-escalation paths.",
        "purpose": "Surface local privilege-escalation opportunities on a Linux host.",
        "when": "Post-access review of a Linux system (or WSL on Windows).",
        "how": "Run against the local Linux/WSL environment and read the flagged vectors.",
        "capabilities": [
            "Enumerates SUID binaries, cron jobs, writable files, kernel/version, stored creds",
        ],
        "caveats": [
            "Linux-focused (detects and uses WSL on Windows); output is verbose.",
            "It enumerates weaknesses - it does not exploit them.",
        ],
    },
    "Auditd": {
        "tagline": "Review Linux auditd logging configuration.",
        "purpose": "Inspect Linux audit rules/logs to assess logging and forensic readiness.",
        "when": "Evaluating detection/forensic coverage on a Linux host.",
        "how": "Run on a Linux host with auditd present.",
        "capabilities": [
            "Audit rule and log inspection",
        ],
        "caveats": [
            "Linux-only; requires auditd to be installed.",
        ],
    },

    # ----------------------------- Hacker Tools -----------------------------
    "FTP Brute": {
        "tagline": "Test an FTP service for weak passwords.",
        "purpose": "Attempt logins against an FTP server to find weak/guessable credentials.",
        "when": "Authorized credential-strength testing of an FTP service.",
        "how": "Enter the target and run; it tries username/password combinations from wordlists.",
        "capabilities": [
            "Automated FTP login attempts against credential lists",
        ],
        "caveats": [
            "This is an ACTIVE attack: it can lock accounts and is very noisy.",
            "Slow, and blocked by rate-limiting/lockout policies.",
        ],
    },
    "Subdomains": {
        "tagline": "Discover an organization's subdomains.",
        "purpose": "Enumerate subdomains of a domain to map external attack surface.",
        "when": "Recon of an organization's internet-facing footprint.",
        "how": "Enter the base domain (e.g. example.com) and run.",
        "capabilities": [
            "DNS/wordlist-based subdomain discovery",
        ],
        "caveats": [
            "DNS-dependent; won't find internal-only names.",
            "High query volume can be noticeable to DNS operators.",
        ],
    },
    "Metasploit": {
        "tagline": "Launch the Metasploit exploitation framework.",
        "purpose": "Test known exploits and run post-exploitation against a target.",
        "when": "Validating exploitability of an identified vulnerability during an authorized pentest.",
        "how": "Launches the Metasploit workflow (msfconsole/meterpreter); select module, set "
               "target, run.",
        "capabilities": [
            "Exploit modules, payload generation, and post-exploitation tooling",
        ],
        "caveats": [
            "OFFENSIVE and powerful - explicit written authorization is mandatory.",
            "Can crash or destabilize target services; will be flagged by AV/EDR.",
            "Requires Metasploit installed.",
        ],
    },
    "Rev Shell": {
        "tagline": "Generate a reverse-shell payload/listener (testing).",
        "purpose": "Produce a reverse-shell command for validating remote access during sanctioned "
                   "testing.",
        "when": "Confirming callback/C2 behavior in an engagement you're authorized to run.",
        "how": "Generate the payload/command and use it on a system you control/are authorized to test.",
        "capabilities": [
            "Reverse-shell command/payload generation",
        ],
        "caveats": [
            "DUAL-USE: only for systems you own or are authorized to test.",
            "Will be detected as malware; misuse carries serious legal risk.",
        ],
    },
    "Packet Interceptor": {
        "tagline": "Reconstruct cleartext messages/files from traffic.",
        "purpose": "Capture and copy cleartext content (messages, files) traversing the network.",
        "when": "Demonstrating the exposure of unencrypted protocols on an authorized segment.",
        "how": "Run on an authorized segment; captured cleartext content is reconstructed.",
        "capabilities": [
            "Reassembles cleartext messages/files from captured packets",
        ],
        "caveats": [
            "HIGHLY SENSITIVE - intercepting communications has wiretap/legal implications.",
            "Only recovers unencrypted content; may require a man-in-the-middle position.",
            "Strict authorization required.",
        ],
    },
    "DDoS Tool": {
        "tagline": "Generate heavy load to test server resilience.",
        "purpose": "Simulate a flood of traffic to test how a server holds up under load.",
        "when": "Authorized load / denial-of-service resilience testing.",
        "how": "Enter the target, set duration and thread count, and run. (This tool has no "
               "'scan own machine' option - it is a stress generator, not a scanner.)",
        "capabilities": [
            "High-volume traffic generation against a target",
        ],
        "caveats": [
            "DESTRUCTIVE/DISRUPTIVE - it can take services offline.",
            "Only against infrastructure you own with written authorization; may violate host/ISP "
            "terms and the law.",
        ],
    },

    # ----------------------------- SQL Injection -----------------------------
    "DB Breacher": {
        "tagline": "Extract data from a vulnerable database.",
        "purpose": "Pull schemas, tables, and records out of a database that has an exploitable flaw.",
        "when": "Demonstrating impact after identifying a database vulnerability (authorized).",
        "how": "Enter the target and run; extracted structure/data is reported.",
        "capabilities": [
            "Schema/table enumeration and record extraction",
        ],
        "caveats": [
            "OFFENSIVE data-access - authorization mandatory.",
            "May expose real PII; handle any recovered data per policy. Can be destructive.",
        ],
    },
    "SQLMap-Lite": {
        "tagline": "Automatically find and exploit SQL injection.",
        "purpose": "Detect SQL injection in web parameters and, where present, enumerate/extract the DB.",
        "when": "Testing a web app's parameters for SQLi on an authorized target.",
        "how": "Enter the target URL (including a parameter), pick a payload list, and run.",
        "capabilities": [
            "SQLi detection, database enumeration, and data extraction",
        ],
        "caveats": [
            "Offensive and noisy; can modify or damage data.",
            "Authorization required.",
        ],
    },
    "XSS-to-SQL": {
        "tagline": "Test XSS that pivots into the database.",
        "purpose": "Look for vulnerabilities that chain client-side XSS into a server-side SQL flaw.",
        "when": "Advanced web-app testing where client and server flaws may combine.",
        "how": "Enter the target and run.",
        "capabilities": [
            "Chained injection testing (XSS -> SQL)",
        ],
        "caveats": [
            "Specialized and offensive; prone to false positives.",
            "Authorization required.",
        ],
    },
    "NoSQL Injector": {
        "tagline": "Test NoSQL databases for injection flaws.",
        "purpose": "Probe NoSQL back-ends (e.g. MongoDB) for injection and auth-bypass issues.",
        "when": "The target application uses a NoSQL datastore.",
        "how": "Enter the target and run.",
        "capabilities": [
            "NoSQL injection and authentication-bypass payload testing",
        ],
        "caveats": [
            "Offensive and back-end-specific; authorization required.",
        ],
    },

    # ----------------------------- Password -----------------------------
    "John The Ripper": {
        "tagline": "Crack password hashes with the real John the Ripper (jumbo).",
        "purpose": "Run the full John the Ripper to recover passwords from hashes and gauge "
                   "password strength/policy. Supports hundreds of hash types and the *2john "
                   "converters (zip/rar/ssh/keepass/…).",
        "when": "Auditing captured hashes (shadow files, NTLM/PWDUMP dumps, application hashes) "
                "or validating password policy you're authorized to test.",
        "how": "First install John once: download 'winX64_1_JtR.zip' from "
               "https://github.com/openwall/john-packages/releases/latest and extract it to a "
               "'tools/john' folder next to the app (so tools/john/.../run/john.exe exists); on "
               "Linux 'sudo apt install john'. Then put your hashes in 'hashes.txt' next to the "
               "app (or type a hash-file path in the box) and run. For raw hashes (md5/sha1/NTLM) "
               "type the format in the box, e.g. Raw-MD5, raw-sha1, NT.",
        "capabilities": [
            "Dictionary + rules (and brute/incremental) cracking of hundreds of hash types",
            "Auto-detects shadow/NTLM/app hashes; includes the *2john file converters",
            "Shows recovered passwords; results persist in John's pot file across runs",
        ],
        "caveats": [
            "Not bundled - you install John once into tools/john (it's large, GPL, and AV-flagged).",
            "Bare raw hashes auto-detect ambiguously (John may pick LM and never crack) - "
            "specify the format in the box for those.",
            "Runs under a time budget that scales with intensity; use Terminate to stop early.",
            "Only crack hashes you're authorized to; store any recovered credentials securely.",
        ],
    },
    "Hydra Brute": {
        "tagline": "Brute-force network login services online.",
        "purpose": "Test live login services (SSH, RDP, HTTP, etc.) for weak credentials.",
        "when": "Authorized online credential-strength testing of a network service.",
        "how": "Enter the target/service and run with username/password lists.",
        "capabilities": [
            "Multi-protocol online brute-forcing",
        ],
        "caveats": [
            "ACTIVE attack: can lock accounts and is very noisy.",
            "May be illegal without authorization; blocked by lockout/rate-limits.",
        ],
    },

    # ----------------------------- Custom Tools -----------------------------
    "Full Audit": {
        "tagline": "Run all core scans against a target in sequence.",
        "purpose": "One-click, broad assessment that chains the core scan tools and aggregates findings.",
        "when": "A comprehensive first pass on a target when you want breadth quickly.",
        "how": "Enter the target and run; it executes the core tools in order - this takes a while.",
        "capabilities": [
            "Orchestrates multiple scanners and consolidates their findings",
        ],
        "caveats": [
            "Long-running and noisy; includes ACTIVE checks - authorization required.",
            "Review each underlying tool's own caveats.",
        ],
    },
    "Custom Cmd": {
        "tagline": "Run any command-line tool against your target.",
        "purpose": "Execute an arbitrary CLI command, using {target} as a placeholder for the address.",
        "when": "You need a tool or option this GUI doesn't wrap.",
        "how": "Enter a command template containing {target} (e.g. 'nmap -sV {target}') and run.",
        "capabilities": [
            "Runs external command-line tools and captures their output",
        ],
        "caveats": [
            "NO SAFETY RAILS - you are responsible for what you run; commands can be destructive.",
            "Only run commands you understand and are authorized to execute.",
        ],
    },
    "Web Fetch": {
        "tagline": "Fetch a site's headers to check it's up.",
        "purpose": "Download a website's response headers to check responsiveness/availability.",
        "when": "A quick 'is it up / what server is it' check.",
        "how": "Enter a URL and run (issues an HTTP HEAD via curl).",
        "capabilities": [
            "Retrieves HTTP response headers",
        ],
        "caveats": [
            "Requires curl; this is a connectivity check, not a security scan.",
        ],
    },
    "NSLookup": {
        "tagline": "Query DNS records for a domain.",
        "purpose": "Look up DNS information (addresses, records) for a domain.",
        "when": "DNS recon of a domain.",
        "how": "Enter a domain and run.",
        "capabilities": [
            "DNS record queries via nslookup",
        ],
        "caveats": [
            "DNS caching can affect results; this is passive recon only.",
        ],
    },
}


_DEFAULT = {
    "tagline": "Security tool.",
    "purpose": "A Layer8 security tool.",
    "when": "See the tool's on-screen options.",
    "how": "Enter a target where required and run.",
    "capabilities": ["See on-screen results."],
    "caveats": [],
}


def get_tool_doc(tool_name: str) -> dict:
    """Return the doc for a tool name (exact match, then substring), else a default.

    The GLOBAL_CAVEAT is always appended so the authorization reminder is never missed.
    """
    doc = TOOL_DOCS.get(tool_name)
    if doc is None:
        # Tolerate names carrying extra text (e.g. "Win Audit (local)").
        for key, val in TOOL_DOCS.items():
            if key in tool_name or tool_name in key:
                doc = val
                break
    if doc is None:
        doc = _DEFAULT
    merged = dict(doc)
    merged["caveats"] = list(doc.get("caveats", [])) + [GLOBAL_CAVEAT]
    return merged
