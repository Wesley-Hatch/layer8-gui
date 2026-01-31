import os
import json
import time

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
    Layer8 is a security auditing platform with tools for:
    - Network: Nmap, Port Scan, Ping Sweep, Sniffer, WiFi Analyzer.
    - Web: Nikto, DirBrute, WPScan.
    - Exploitation: Metasploit, SQLMap, Rev Shell, DDoS Tool.
    - System: Win Audit, LinPeas.
    
    Tools often use functional simulation if real binaries (like nmap) are missing.
    """

    def __init__(self, api_key=None, model="claude-sonnet-4-5"):
        self._load_credentials(api_key)
        self.model = model
        self.client = self._init_client()

    def _load_credentials(self, api_key):
        # Load from multiple locations for robustness
        base_dir = os.path.dirname(os.path.abspath(__file__))
        env_dirs = [base_dir, os.path.join(base_dir, ".env"), os.path.dirname(base_dir)]
        
        for d in env_dirs:
            load_dotenv(os.path.join(d, ".env"), override=True)
            key_file = os.path.join(d, "claude_api_key.txt")
            if os.path.exists(key_file):
                try:
                    with open(key_file, "r") as f:
                        os.environ["ANTHROPIC_API_KEY"] = f.read().strip()
                except: pass

        try:
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        except Exception:
            self.api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")

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

    def analyze_domain_target(self, target, findings):
        """Specifically analyzes a target domain/IP for an Admin user."""
        if not target:
            return "No target specified for analysis."

        system_prompt = f"""
        You are the Layer8 Admin AI Analyst.
        {self.PLATFORM_INFO}
        
        Your task is to analyze the target: {target}
        Based on existing findings and common security practices, provide:
        1. DOMAIN/TARGET OVERVIEW
        2. POTENTIAL ATTACK VECTORS
        3. SUGGESTED SCAN COMMANDS (Specific commands to run on this target)
        4. REMEDIATION STRATEGY
        
        Keep suggestions technical and actionable.
        
        AUTONOMOUS COMMAND EXECUTION:
        You can request to run any security command available on the platform.
        To run a command, you MUST use the following format on a new line:
        EXECUTE: [command]
        
        If you have found a definitive answer or enough information, STOP and present your findings. Do not suggest more commands if the analysis is complete. To save tokens, be as direct as possible.
        
        Example:
        EXECUTE: nmap -sV {target}
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
                    max_tokens=1500,
                    system=system_prompt,
                    messages=[{"role": "user", "content": [{"type": "text", "text": user_prompt}]}]
                )
                report = "".join([block.text for block in response.content if hasattr(block, 'text')])
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
        You are the Layer8 Admin AI Assistant.
        {self.PLATFORM_INFO}
        
        Your task is to assist the Admin in analyzing the target: {target}
        
        AUTONOMOUS COMMAND EXECUTION:
        You can request to run any security command available on the platform (nmap, nikto, gobuster, sqlmap, etc.).
        To run a command, you MUST use the following format on a new line:
        EXECUTE: [command]
        
        If you have found a definitive answer or enough information, STOP and present your findings. Do not suggest more commands if the analysis is complete. To save tokens, be as direct as possible.
        
        Example:
        I will now check for open ports.
        EXECUTE: nmap -sV {target}
        
        The GUI will capture the output and provide it to you in the next turn.
        
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
                    max_tokens=1500,
                    system=system_prompt,
                    messages=formatted_messages
                )
                ai_msg = "".join([block.text for block in response.content if hasattr(block, 'text')])
                
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
                max_tokens=1500,
                system=system_prompt,
                messages=[{"role": "user", "content": [{"type": "text", "text": user_prompt}]}]
            )
            
            report = "".join([block.text for block in response.content if hasattr(block, 'text')])
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
