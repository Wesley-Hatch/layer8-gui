import os
import json
import time
from secure_logger import get_logger

# Set up secure logging
logger = get_logger('ai')

try:
    import anthropic
except ImportError:
    anthropic = None

from dotenv import load_dotenv

class AIAnalyzer:
    """
    Redesigned AI Security Assistant logic from scratch.
    Focuses on clean data processing, robust API interaction, and helpful security insights.
    """

    PLATFORM_INFO = """
    Layer8 is a security auditing platform. All tools do REAL work against the
    target (no simulated results) and need no external APIs.
    """

    # Native tools the AI can run via the EXECUTE protocol. Each runs against the
    # operator-set target. DDoS is intentionally NOT AI-runnable (destructive;
    # operate it manually). These are the exact names to use after "EXECUTE:".
    AI_TOOLS = {
        "port_scan": "TCP port scan of the target",
        "ping_sweep": "Ping-sweep the target's /24 subnet",
        "nmap": "Nmap service+vuln scan (uses real nmap; built-in TCP scan if nmap absent)",
        "nikto": "Web server vulnerability/misconfig scan",
        "dirbrute": "Directory/file brute force on a web target",
        "cve_search": "Offline service/version fingerprinting (banners + HTTP headers)",
        "wpscan": "WordPress detection + plugin enumeration",
        "subdomains": "Subdomain enumeration via DNS",
        "ftp_brute": "FTP weak-credential test",
        "hydra": "Online login brute force (FTP/HTTP)",
        "sqlmap": "SQL injection probing",
        "xss_sql": "XSS-to-SQL cross-vector probing",
        "nosql": "NoSQL injection probing",
        "db_breach": "Probe for exposed database/API endpoints",
        "camera_finder": "Discover IP cameras on the subnet",
        "firewall_audit": "Firewall configuration audit",
        "win_audit": "Windows configuration audit (local machine)",
        "metasploit": "Suggest Metasploit modules from open ports",
        "web_fetch": "Fetch the target's HTTP response headers",
        "nslookup": "DNS lookup of the target",
        "full_audit": "Run all core scans against the target",
    }

    # Compliance control catalog (kept self-contained so it works in the frozen
    # GUI, which doesn't bundle the win_audit package). The AI maps findings to
    # these exact control IDs in its report.
    COMPLIANCE_REFERENCE = """
    Map findings to these frameworks using these exact control IDs:
    - CJIS Security Policy: 5.4 Auditing & Accountability, 5.5 Access Control,
      5.6 Identification & Authentication, 5.7 Configuration Management,
      5.8 Media Protection, 5.10 System & Communications Protection & Integrity.
    - CIS Controls v8: CIS-3 Data Protection, CIS-4 Secure Configuration,
      CIS-5 Account Management, CIS-6 Access Control, CIS-7 Vulnerability Management,
      CIS-8 Audit Log Management, CIS-10 Malware Defenses, CIS-12 Network
      Infrastructure, CIS-13 Network Monitoring.
    - NIST SP 800-53: AC-2, AC-3, AC-6, AC-17, AU-2, AU-6, AU-12, CM-5, CM-6, CM-7,
      IA-5, RA-5, SC-7, SC-8, SC-13, SC-23, SC-28, SI-2, SI-3, SI-4.
    """

    @staticmethod
    def _extract_text(response):
        """Pull text from a response, surfacing refusals and empty completions
        clearly instead of returning a silent blank."""
        try:
            if getattr(response, "stop_reason", None) == "refusal":
                det = getattr(response, "stop_details", None)
                cat = getattr(det, "category", None) if det else None
                expl = getattr(det, "explanation", None) if det else None
                msg = "[AI DECLINED THIS REQUEST] The model would not complete this task"
                if cat:
                    msg += f" (category: {cat})"
                msg += "."
                if expl:
                    msg += f"\nReason: {expl}"
                msg += "\nRephrase the request, or confirm this is an authorized engagement."
                return msg
            text = "".join(getattr(b, "text", "") for b in response.content if hasattr(b, "text"))
            text = text.strip()
            if not text:
                return "[AI returned no content - it stopped without answering. Try again or rephrase your request.]"
            return text
        except Exception as e:
            return f"[!] Could not read the AI response: {e}"

    @classmethod
    def _tools_help(cls):
        lines = [f"      - {name}: {desc}" for name, desc in cls.AI_TOOLS.items()]
        return "\n".join(lines)

    @classmethod
    def _execute_protocol(cls, target):
        return f"""
        RUNNING TOOLS (attack/scan the authorized target):
        You can run Layer8's real tools against the target. To run one, put this on
        its OWN line, exactly:
          EXECUTE: <tool_name>
        Available <tool_name> values:
{cls._tools_help()}
        You may also run an installed command-line tool directly, e.g.:
          EXECUTE: nmap -sV {target}
        After each run the GUI feeds the output back to you. Chain tools as needed:
        recon first (port_scan / cve_search / nmap), then targeted tests.
        Only operate on the authorized target ({target}). Do not fabricate results.
        When you have enough information, STOP running tools and write a final report
        with: SUMMARY, FINDINGS (with severity), ATTACK PATH, and REMEDIATION.

        If you cannot or will not perform a requested action - policy, safety, lack of
        authorization, or a tool you decline to run - SAY SO EXPLICITLY in your reply
        and explain why. Never stop silently or return an empty response.
        """

    def __init__(self, api_key=None, model="claude-opus-5-5"):
        self._load_credentials(api_key)
        self.model = model
        self.client = self._init_client()

    @staticmethod
    def _config_dir():
        """Per-user config dir where the operator's own API key is persisted."""
        import platform
        if platform.system() == "Windows":
            base = os.path.join(os.getenv("APPDATA", os.path.expanduser("~")), "Layer8")
        else:
            base = os.path.join(os.path.expanduser("~"), ".config", "layer8")
        try:
            os.makedirs(base, exist_ok=True)
        except Exception:
            pass
        return base

    def save_api_key(self, key):
        """Persist the operator's own API key so they don't re-enter it each time.
        Stored in the per-user config dir (their machine, their key)."""
        key = (key or "").strip()
        if not key:
            return False
        try:
            with open(os.path.join(self._config_dir(), "claude_api_key.txt"), "w", encoding="utf-8") as f:
                f.write(key)
            self.api_key = key
            os.environ["ANTHROPIC_API_KEY"] = key
            self.client = self._init_client()
            return True
        except Exception as e:
            logger.error(f"Failed to save API key: {e}")
            return False

    def _load_credentials(self, api_key):
        # Load from multiple locations for robustness
        base_dir = os.path.dirname(os.path.abspath(__file__))
        env_dirs = [base_dir, os.path.join(base_dir, ".env"), os.path.dirname(base_dir),
                    self._config_dir()]

        for d in env_dirs:
            load_dotenv(os.path.join(d, ".env"), override=True)
            key_file = os.path.join(d, "claude_api_key.txt")
            if os.path.exists(key_file):
                try:
                    with open(key_file, "r") as f:
                        os.environ["ANTHROPIC_API_KEY"] = f.read().strip()
                except Exception as e:
                    logger.error(f"Failed to read key file: {e}")

        try:
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        except Exception:
            self.api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")

        if self.api_key:
            logger.info("AI credentials loaded", context={'api_key': self.api_key})
        else:
            logger.warning("No AI API key found")

    def _init_client(self):
        if not anthropic or not self.api_key:
            return None
        
        try:
            base_url = os.getenv("ANTHROPIC_BASE_URL")
            if base_url and "/v1" in base_url:
                base_url = base_url.split("/v1")[0]
            
            return anthropic.Anthropic(api_key=self.api_key, base_url=base_url)
        except:
            return None

    def analyze_session(self, history, findings, mode="Both"):
        """Main entry point for session analysis."""
        if not history and not findings:
            return "No activity recorded in this session yet. Run some tools first!"

        if self.client:
            return self._analyze_with_claude(history, findings, mode)
        else:
            return self._analyze_locally(history, findings, mode)

    def generate_report(self, target, findings, history, transcript=""):
        """Produce a written penetration-test report from the session's real
        findings/history (and optional AI chat transcript). Returns markdown."""
        data = self._build_data_package(history or [], findings or [])
        if transcript:
            data += "\n### AI OPERATOR TRANSCRIPT (excerpt) ###\n" + transcript[-4000:]

        system_prompt = f"""
        You are the Layer8 AI Security Operator writing a penetration-test report
        for an AUTHORIZED engagement against: {target or 'the assessed systems'}.
        Base the report ONLY on the real session data provided - do not invent
        findings. Produce clean Markdown with these sections:
        1. Executive Summary
        2. Scope & Target
        3. Findings (each: title, severity Critical/High/Medium/Low/Info, evidence, impact)
        4. Attack Path / Narrative
        5. Remediation & Recommendations (prioritized)
        6. Compliance Mapping (CJIS / CIS v8 / NIST 800-53): a table mapping each
           finding to the affected control(s), and a short per-framework rollup of
           which controls PASS vs. FAIL/REVIEW based on the findings.
        7. Appendix: tools run
        {self.COMPLIANCE_REFERENCE}
        Note in the compliance section that this is a pragmatic mapping to aid an
        audit, to be verified against the authoritative control set - not a
        certification.
        If the data is thin, say so rather than padding.
        """
        if self.client:
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4000,
                    system=system_prompt,
                    messages=[{"role": "user", "content": [{"type": "text", "text": data}]}],
                )
                report = self._extract_text(response)
                header = f"# Layer8 Penetration Test Report\n**Target:** {target or 'N/A'}  \n**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                return header + report
            except Exception as e:
                return self._local_report(target, findings, history) + f"\n\n[!] AI report error: {e}"
        return self._local_report(target, findings, history)

    def _local_report(self, target, findings, history):
        """Report generator that works with no AI connection (rule-based)."""
        lines = [f"# Layer8 Penetration Test Report (local)",
                 f"**Target:** {target or 'N/A'}  ",
                 f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}", "",
                 "## Summary",
                 f"- Tools run: {len(history or [])}",
                 f"- Findings recorded: {len(findings or [])}", "", "## Findings"]
        seen = set()
        for f in (findings or []):
            s = str(f)
            if s not in seen:
                lines.append(f"- {s}")
                seen.add(s)
        lines += ["", "## Tools Run"]
        for item in (history or [])[-30:]:
            lines.append(f"- [{item.get('time')}] {item.get('cmd')} -> {item.get('status')}")
        lines += ["", "## Compliance Mapping (CJIS / CIS v8 / NIST 800-53)",
                  "_Offline mode: for a structured per-control compliance report run the_",
                  "_Windows auditor (`python -m win_audit`), which emits a `.compliance.csv`._",
                  "_Add an API key here for an AI-generated compliance mapping of these findings._"]
        lines += ["", "_No AI connection; this is a raw rule-based report. Add an API key for a full narrative report._"]
        return "\n".join(lines)

    def analyze_domain_target(self, target, findings):
        """Specifically analyzes a target domain/IP for an Admin user."""
        if not target:
            return "No target specified for analysis."

        system_prompt = f"""
        You are the Layer8 AI Security Operator for AUTHORIZED penetration testing.
        {self.PLATFORM_INFO}

        Target: {target}
        Assess it: run reconnaissance, then targeted tests, using the tools below.
        {self._execute_protocol(target)}
        Be direct and technical to save tokens.
        """

        user_prompt = f"TARGET: {target}\n\nEXISTING FINDINGS:\n"
        seen = set()
        for f in findings:
            f_str = str(f)
            if f_str not in seen:
                user_prompt += f"- {f_str}\n"
                seen.add(f_str)

        if self.client:
            try:
                # Use explicit content blocks for better compatibility and to avoid 400 errors
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4000,
                    system=system_prompt,
                    messages=[{"role": "user", "content": [{"type": "text", "text": user_prompt}]}]
                )
                report = self._extract_text(response)
                return f"--- ADMIN AI DOMAIN ANALYSIS: {target} ---\n\n{report}"
            except Exception as e:
                return f"[!] AI Error: {str(e)}\n\nFalling back to local domain analysis...\n\n" + self._local_domain_analysis(target, findings)
        else:
            return self._local_domain_analysis(target, findings)

    def admin_chat(self, target, findings, message, chat_history):
        """Interactive chat with the Admin AI Assistant."""
        if not target:
            return "No target specified for analysis.", chat_history

        system_prompt = f"""
        You are the Layer8 AI Security Operator for AUTHORIZED penetration testing.
        {self.PLATFORM_INFO}

        You assist the operator in assessing the target: {target}
        {self._execute_protocol(target)}

        CURRENT FINDINGS FOR CONTEXT:
        """
        seen = set()
        for f in findings:
            f_str = str(f)
            if f_str not in seen:
                system_prompt += f"- {f_str}\n"
                seen.add(f_str)

        if self.client:
            try:
                # Ensure chat_history only contains role/content and use explicit content blocks
                # This fixes the 400 error: "messages.1.content.0: Input should be a valid dictionary"
                formatted_messages = []
                for m in chat_history:
                    # Filter out any non-text/empty content and wrap in list of blocks
                    content_text = m.get("content", "")
                    if content_text:
                        formatted_messages.append({
                            "role": m["role"],
                            "content": [{"type": "text", "text": content_text}]
                        })

                # Add current user message
                formatted_messages.append({
                    "role": "user",
                    "content": [{"type": "text", "text": message}]
                })

                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4000,
                    system=system_prompt,
                    messages=formatted_messages
                )
                ai_msg = self._extract_text(response)
                
                # We don't update chat_history here, the GUI will handle it to keep it in sync
                return ai_msg
            except Exception as e:
                return f"[!] AI Chat Error: {str(e)}"
        else:
            # Simple local chat fallback
            if "nmap" in message.lower():
                return f"Local Assistant: Searching for ports on {target}...\nEXECUTE: nmap -sV {target}"
            return f"Local Assistant: I received your message: '{message}'. (Local mode has limited chat capabilities)"

    def _local_domain_analysis(self, target, findings):
        """Local fallback for domain analysis."""
        report = f"--- LOCAL ADMIN ANALYSIS: {target} ---\n"
        report += "Analyzing target based on common patterns...\n\n"
        
        ports = [f.get('Port') for f in findings if f.get('Port')]
        
        report += "1. TARGET OVERVIEW\n"
        report += f"- Target: {target}\n"
        if ports:
            report += f"- Identified Ports: {list(set(ports))}\n"
        else:
            report += "- No ports identified yet. Discovery recommended.\n"
            
        report += "\n2. SUGGESTED COMMANDS\n"
        if target.replace(".", "").isdigit(): # Likely IP
            report += f"- nmap -sV -sC -T4 {target}\n"
            report += f"- nmap --script vuln {target}\n"
        else: # Likely Domain
            report += f"- dig {target} ANY\n"
            report += f"- gobuster dir -u http://{target} -w common.txt\n"
            
        report += "\n3. ACTIONABLE STEPS\n"
        report += "- Perform full port scan if not already done.\n"
        report += "- Check for common web vulnerabilities if HTTP/HTTPS are open."
        
        return report

    def _analyze_with_claude(self, history, findings, mode):
        system_prompt = f"""
        You are the Layer8 AI Security Assistant.
        {self.PLATFORM_INFO}
        
        Your goal is to provide expert security analysis based on the provided session data.
        Mode: {mode}
        
        Format your report with:
        1. SUMMARY OF ACTIVITY
        2. KEY VULNERABILITIES IDENTIFIED
        3. RECOMMENDED ACTIONS ({mode})
        4. OPERATOR ADVISORY
        """

        user_prompt = self._build_data_package(history, findings)

        try:
            # Use explicit content blocks for better compatibility and to avoid 400 errors
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                system=system_prompt,
                messages=[{"role": "user", "content": [{"type": "text", "text": user_prompt}]}]
            )
            
            report = self._extract_text(response)
            return f"--- CLAUDE AI SECURITY REPORT ({time.strftime('%H:%M:%S')}) ---\n\n{report}"
        
        except Exception as e:
            error_msg = self._handle_api_error(e)
            return f"{error_msg}\n\nFalling back to local analysis...\n\n" + self._analyze_locally(history, findings, mode)

    def _build_data_package(self, history, findings):
        """Prepares a clean text package for the AI."""
        package = "SESSION DATA:\n\n"
        
        package += "### COMMAND HISTORY ###\n"
        for item in history[-10:]: # Last 10 tasks for context
            package += f"- [{item.get('time')}] {item.get('cmd')} -> {item.get('status')}\n"
            if item.get('finding'):
                package += f"  Finding: {item.get('finding')}\n"
        
        package += "\n### STRUCTURED FINDINGS ###\n"
        # Deduplicate and summarize findings
        seen = set()
        for f in findings:
            f_str = str(f)
            if f_str not in seen:
                package += f"- {f_str}\n"
                seen.add(f_str)
                if len(seen) > 30: # Cap findings to avoid token bloat
                    package += "... (truncated)\n"
                    break
        
        return package

    def _handle_api_error(self, e):
        logger.error(f"AI API Error: {e}", exc_info=True)
        if "401" in str(e):
            return "[!] API Authentication Error: Invalid API Key."
        if "404" in str(e):
            return f"[!] API Model Error: The model '{self.model}' was not found or is unavailable."
        if "429" in str(e):
            return "[!] API Rate Limit: Too many requests or insufficient credits."
        return f"[!] API Error: {str(e)}"

    def _analyze_locally(self, history, findings, mode):
        """Robust rule-based local analysis."""
        report = f"--- LOCAL SECURITY ANALYSIS ({time.strftime('%H:%M:%S')}) ---\n"
        report += "Note: No AI connection; using rule-based engine.\n\n"
        
        ports = [f.get('Port') for f in findings if f.get('Port')]
        issues = [f.get('Issue') for f in findings if f.get('Issue')]
        
        report += "1. SUMMARY\n"
        report += f"- Analyzed {len(history)} tasks.\n"
        report += f"- Identified {len(ports)} open ports and {len(issues)} specific security issues.\n\n"
        
        report += "2. RECOMMENDATIONS\n"
        if mode in ["Offensive (Penetrate)", "Both"]:
            report += "Offensive Insights:\n"
            if ports:
                report += f"- Target has open ports: {list(set(ports))}. Attempt service versioning.\n"
            if 80 in ports or 443 in ports:
                report += "- Web services detected. Use Nikto or DirBrute for further discovery.\n"
            if not ports and not issues:
                report += "- No immediate entry points. Try wider subnet scanning.\n"
        
        if mode in ["Defensive (Patch)", "Both"]:
            report += "\nDefensive Insights:\n"
            for issue in set(issues):
                report += f"- [!] Resolve identified issue: {issue}\n"
            if ports:
                report += "- Close unnecessary exposed ports to reduce attack surface.\n"
                
        report += "\n3. NEXT STEPS\n"
        report += "- Run 'Full Audit' for a comprehensive view.\n"
        report += "- Export findings to Excel for documentation."
        
        return report
