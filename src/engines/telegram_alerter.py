#!/usr/bin/env python3
"""
LogSentinel Pro — Telegram Alert Integration
Sends real-time CRITICAL/HIGH threat alerts to a Telegram bot.
"""
import os
import time
import threading
from collections import defaultdict

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

# Find .env from project root (two dirs up from src/engines/)
_this_dir = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(_this_dir, '..', '..', '.env')


class TelegramAlerter:
    """
    Sends threat alerts to Telegram with rate limiting.
    Rate limit: max 1 alert per threat type per 30 seconds.
    """

    def __init__(self):
        if DOTENV_AVAILABLE:
            load_dotenv(dotenv_path)
        self.bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}" if self.bot_token else ""

        # Rate limiting: track last alert time per threat type
        self._last_alert_time = defaultdict(float)
        self._rate_limit_seconds = 30  # 1 alert per type per 30s
        self._lock = threading.Lock()
        self._alert_count = 0

        if self.bot_token and not self.chat_id:
            print("[Telegram] No CHAT_ID found. Auto-discovering from bot messages...")
            self.auto_discover_chat_id()
            
        if self.is_configured():
            self._start_interactive_listener()

    def _start_interactive_listener(self):
        """Background thread to listen for Telegram button clicks."""
        if not REQUESTS_AVAILABLE:
            return
            
        def poll():
            offset = None
            while True:
                try:
                    url = f"{self.api_url}/getUpdates"
                    params = {"timeout": 30}
                    if offset:
                        params["offset"] = offset
                    resp = requests.get(url, params=params, timeout=35)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("ok") and data.get("result"):
                            for update in data["result"]:
                                offset = update["update_id"] + 1
                                if "callback_query" in update:
                                    self._handle_callback(update["callback_query"])
                except Exception:
                    pass
                time.sleep(2)
                
        # Run the UI listener in a resilient background thread
        listener_thread = threading.Thread(target=poll, daemon=True)
        listener_thread.start()

    def _handle_callback(self, query: dict):
        """Processes an interactive button click and reports action to the chat."""
        callback_id = query["id"]
        data = query.get("data", "")
        message = query.get("message", {})
        message_id = message.get("message_id")
        chat_id = message.get("chat", {}).get("id")
        
        # Determine logical action response and the new button state
        action_text = ""
        popup_text = ""
        new_keyboard = message.get("reply_markup", {}).get("inline_keyboard", [])
        
        # Helper to toggle buttons
        def replace_button(old_data, new_text, new_data):
            for row in new_keyboard:
                for btn in row:
                    if btn.get("callback_data") == old_data:
                        btn["text"] = new_text
                        btn["callback_data"] = new_data
                        
        def replace_row(old_data, new_row_list):
            for i, row in enumerate(new_keyboard):
                for btn in row:
                    if btn.get("callback_data") == old_data:
                        new_keyboard[i] = new_row_list
                        return

        if data.startswith("block_ip_"):
            ip = data.replace("block_ip_", "")
            popup_text = f"Requires confirmation..."
            
            # Sub-menu row
            confirm_row = [
                {"text": f"✔️ YES, BAN LOCALHOST", "callback_data": f"confirm_block_{ip}"} if ip in ("127.0.0.1", "0.0.0.0", "localhost") else {"text": f"✔️ YES, BAN {ip}", "callback_data": f"confirm_block_{ip}"},
                {"text": "❌ CANCEL", "callback_data": f"cancel_block_{ip}"}
            ]
            replace_row(data, confirm_row)
            
            # Don't send a chat message, just update buttons
            action_text = ""

        elif data.startswith("confirm_block_"):
            ip = data.replace("confirm_block_", "")
            import subprocess
            try:
                cmd = f'netsh advfirewall firewall add rule name="LogSentinel-Block-{ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                popup_text = f"Firewall block verified."
                action_text = f"🛑 **ACTION EXECUTED OVER REAL-TIME SOAR:**\nOS Firewall rule deployed successfully. Traffic from `{ip}` is **REJECTED**."
            except Exception as e:
                popup_text = f"Block executed (Simulated)."
                action_text = f"🛑 **ACTION SIMULATED:**\nIP Address `{ip}` blocked virtually (Admin Firewall privileges missing for netsh execution)."
            replace_row(data, [{"text": f"🟢 Unblock IP ({ip})", "callback_data": f"unblock_ip_{ip}"}])
            
        elif data.startswith("cancel_block_"):
            ip = data.replace("cancel_block_", "")
            popup_text = "Ban cancelled."
            action_text = ""
            replace_row(data, [{"text": f"🛑 Block IP ({ip})", "callback_data": f"block_ip_{ip}"}])
            
        elif data.startswith("unblock_ip_"):
            ip = data.replace("unblock_ip_", "")
            import subprocess
            try:
                cmd = f'netsh advfirewall firewall delete rule name="LogSentinel-Block-{ip}"'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                popup_text = f"Firewall rule removed."
                action_text = f"🟢 **ACTION EXECUTED OVER REAL-TIME SOAR:**\nOS Firewall rule was successfully deleted. Traffic from `{ip}` is **ALLOWED**."
            except Exception as e:
                popup_text = f"Unblock executed (Simulated)."
                action_text = f"🟢 **ACTION SIMULATED:**\nIP Address `{ip}` unblocked virtually (Admin privileges missing)."
            replace_button(data, f"🛑 Block IP ({ip})", f"block_ip_{ip}")

        elif data.startswith("ignore_"):
            inc = data.replace("ignore_", "")
            popup_text = "Incident marked as FP."
            action_text = f"✅ **STATUS UPDATE:** Incident `{inc}` has been marked as a False Positive by the SOC team."
            replace_button(data, "🔄 Re-open Case", f"reopen_{inc}")
            
        elif data.startswith("reopen_"):
            inc = data.replace("reopen_", "")
            popup_text = "Incident re-opened."
            action_text = f"🔄 **STATUS UPDATE:** Incident `{inc}` has been re-opened for analysis."
            replace_button(data, "✅ Ignore (False Positive)", f"ignore_{inc}")

        elif data.startswith("investigate_"):
            inc = data.replace("investigate_", "")
            popup_text = "Case assigned to you."
            action_text = f"🔍 **STATUS UPDATE:** Active investigation initialized for Incident `{inc}`. Telemetry locked."
            replace_button(data, "🔒 Close Case", f"close_{inc}")
            
        elif data.startswith("close_"):
            inc = data.replace("close_", "")
            popup_text = "Case closed."
            action_text = f"🔒 **STATUS UPDATE:** Investigation for Incident `{inc}` has been marked as closed."
            replace_button(data, "🔍 Investigate", f"investigate_{inc}")
        else:
            return

        # 1. Answer callback to stop loading spinner and show a toast popup
        try:
            requests.post(f"{self.api_url}/answerCallbackQuery", json={
                "callback_query_id": callback_id,
                "text": popup_text,
                "show_alert": False
            })
        except Exception:
            pass
            
        # 2. Add the action response to the chat 
        if action_text:
            try:
                requests.post(f"{self.api_url}/sendMessage", json={
                    "chat_id": chat_id,
                    "text": action_text,
                    "parse_mode": "Markdown",
                    "reply_to_message_id": message_id
                })
            except Exception:
                pass
                
        # 3. Update the interactive buttons to reflect the new state
        try:
            requests.post(f"{self.api_url}/editMessageReplyMarkup", json={
                "chat_id": chat_id,
                "message_id": message_id,
                "reply_markup": {"inline_keyboard": new_keyboard}
            })
        except Exception:
            pass

    def is_configured(self) -> bool:
        """Check if Telegram is properly configured."""
        return bool(self.bot_token and self.chat_id)

    def auto_discover_chat_id(self):
        """Polls telegram to find the user chat id from the latest incoming message."""
        if not REQUESTS_AVAILABLE:
            return
        try:
            response = requests.get(f"{self.api_url}/getUpdates", timeout=5)
            data = response.json()
            if data.get("ok") and data["result"]:
                last_update = data["result"][-1]
                if "message" in last_update:
                    chat_id = str(last_update["message"]["chat"]["id"])
                    self.chat_id = chat_id
                    self.save_chat_id(chat_id)
                    print(f"[*] Telegram Auto-Discovery successful! Bound to Chat ID: {chat_id}")
                    self.send_alert(
                        "✅ LogSentinel Pro Enterprise is now securely bound to this chat.\n"
                        "You will receive active threat intelligence alerts here.",
                        "🛡️ Security Orchestrator Online"
                    )
                    return
            print("[-] Telegram Auto-Discovery failed. Send a message to your bot and restart!")
        except Exception as e:
            print(f"[-] Telegram Auto-Discovery Error: {e}")

    def save_chat_id(self, chat_id):
        """Save discovered chat ID back to .env."""
        try:
            if not os.path.exists(dotenv_path):
                return
            with open(dotenv_path, "r") as f:
                lines = f.readlines()
            found = False
            with open(dotenv_path, "w") as f:
                for line in lines:
                    if line.startswith("TELEGRAM_CHAT_ID="):
                        f.write(f"TELEGRAM_CHAT_ID={chat_id}\n")
                        found = True
                    else:
                        f.write(line)
                if not found:
                    f.write(f"TELEGRAM_CHAT_ID={chat_id}\n")
        except Exception:
            pass

    def send_alert(self, message: str, title: str = "🚨 LOGSENTINEL ALERT", reply_markup: dict = None) -> bool:
        """Sends a markdown formatted alert to the telegram admin."""
        if not REQUESTS_AVAILABLE or not self.bot_token or not self.chat_id:
            return False

        text = f"*{title}*\n\n{message}"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup

        try:
            resp = requests.post(f"{self.api_url}/sendMessage", json=payload, timeout=5)
            if resp.status_code == 200:
                self._alert_count += 1
                return True
            return False
        except Exception:
            return False

    def send_threat_alert(self, threat: dict) -> bool:
        """
        Send a threat alert with rate limiting.
        Only sends for CRITICAL and HIGH severity.
        Groups by Attacker IP to prevent alert fatigue!
        """
        severity = threat.get("severity", "LOW")
        if severity not in ("CRITICAL", "HIGH"):
            return False

        threat_type = threat.get("type", "UNKNOWN")
        match = threat.get("match", threat.get("details", "—"))
        
        # Extract IP early for rate limiting
        import re
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', match)
        attacker_ip = ip_match.group(0) if ip_match else "UNKNOWN_IP"
        
        now = time.time()

        with self._lock:
            # Rate limit by IP address instead of threat type! Max 1 alert per minute per IP.
            last_time = self._last_alert_time.get(attacker_ip, 0)
            if now - last_time < 60:
                return False  # Rate limited (already warned about this IP)
            self._last_alert_time[attacker_ip] = now

        # Build alert message
        sev_emoji = "🔴" if severity == "CRITICAL" else "🟠"
        mitre = threat.get("mitre", "—")
        timestamp = threat.get("timestamp", time.strftime("%H:%M:%S"))
        
        # Determine incident ID
        incident_id = f"INC-{int(now):X}"

        msg = (
            f"*{sev_emoji} {severity} THREAT ACTIVITY DETECTED*\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"**Attacker IP:** `{attacker_ip}`\n"
            f"**First Seen Event:** `{threat_type}`\n"
            f"**Incident ID:** `{incident_id}`\n"
            f"**Timestamp:** `{timestamp}` UTC\n"
            f"**MITRE Framework:** `{mitre}`\n\n"
            f"**🔍 Telemetry Analysis:**\n"
            f"```text\n{match[:400]}\n```\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ _Subsequent alerts from this IP are temporarily suppressed. Take action below._"
        )
        
        # Determine basic attacker IP if possible
        import re
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', match)
        attacker_ip = ip_match.group(0) if ip_match else "UNKNOWN_IP"

        # Interactive buttons payload
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": f"🛑 Block IP ({attacker_ip})", "callback_data": f"block_ip_{attacker_ip}"}
                ],
                [
                    {"text": "✅ Ignore (False Positive)", "callback_data": f"ignore_{incident_id}"},
                    {"text": "🔍 Investigate", "callback_data": f"investigate_{incident_id}"}
                ]
            ]
        }

        # Fire in background thread to not block the monitor
        threading.Thread(
            target=self.send_alert,
            args=(msg, f"🛡️ LOGSENTINEL PRO SIEM TICKET", reply_markup),
            daemon=True
        ).start()
        return True

    def send_report(self, report_type: str, total_logs: int, total_alerts: int, critical_count: int, high_count: int) -> bool:
        """Sends a structured daily/weekly report to Telegram."""
        if not REQUESTS_AVAILABLE or not self.bot_token or not self.chat_id:
            return False

        text = (
            f"📊 *SECURITY REPORT: {report_type.upper()}*\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"📥 *Logs Processed*: `{total_logs:,}`\n"
            f"⚠️ *Total Alerts*: `{total_alerts}`\n"
            f"🛑 *CRITICAL Events*: `{critical_count}`\n"
            f"🔥 *HIGH Events*: `{high_count}`\n\n"
            f"💡 *Summary*: {(total_alerts/max(total_logs, 1))*100:.2f}% of processed "
            f"traffic triggered threat detection. Action required on {critical_count} critical nodes."
        )
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            requests.post(f"{self.api_url}/sendMessage", json=payload, timeout=5)
            return True
        except Exception:
            return False


# Lazy singleton — only initialized when accessed
_telegram_instance = None

def get_telegram_alerter() -> TelegramAlerter:
    """Get or create the global TelegramAlerter instance."""
    global _telegram_instance
    if _telegram_instance is None:
        _telegram_instance = TelegramAlerter()
    return _telegram_instance

# Backward-compatible alias
telegram = None
try:
    telegram = get_telegram_alerter()
except Exception:
    pass
