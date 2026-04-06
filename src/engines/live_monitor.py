"""
LogSentinel Pro — Live Monitor Engine
Real-time log ingestion (file tailing + UDP Syslog) with Rich Live Dashboard.
"""

import time
import threading
import queue
import socketserver
import re
from typing import List, Dict, Optional
from datetime import datetime
from collections import defaultdict
import os

# Telegram alerter (lazy import)
TELEGRAM_ALERTER = None
try:
    from telegram_alerter import get_telegram_alerter
    TELEGRAM_ALERTER = get_telegram_alerter()
    if TELEGRAM_ALERTER and TELEGRAM_ALERTER.is_configured():
        pass  # Configured
    else:
        TELEGRAM_ALERTER = None
except Exception:
    pass

try:
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.align import Align
    from rich.console import Console
    from rich.text import Text
    from rich.box import ROUNDED, HEAVY, DOUBLE
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console()


# ═══════════════════════════════════════════════════════════════
#  SYSLOG UDP HANDLER
# ═══════════════════════════════════════════════════════════════

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handles incoming UDP syslog packets."""
    def handle(self):
        data = bytes.decode(self.request[0].strip(), errors='ignore')
        if hasattr(self.server, "event_queue"):
            self.server.event_queue.put(data)


# ═══════════════════════════════════════════════════════════════
#  LIVE MONITOR ENGINE
# ═══════════════════════════════════════════════════════════════

class LiveMonitor:
    """
    Production-grade real-time log monitor with:
    - File tailing (tail -f equivalent)
    - UDP Syslog network listener
    - Rich Live Dashboard with auto-refresh
    - Raw log stream with threat highlighting
    """

    def __init__(self, parser_class, analyzer_instance, threat_engine=None):
        self.parser = parser_class
        self.analyzer = analyzer_instance
        self.threat_engine = threat_engine

        self.event_queue = queue.Queue()
        self.recent_threats = []
        self.recent_logs = []          # Raw log lines with metadata
        self.severity_counts = defaultdict(int)
        self.attack_types = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.stats = {
            "events_processed": 0,
            "threats_detected": 0,
            "events_parsed": 0,
            "start_time": None,
        }
        self.running = False
        self.threads = []
        self._server = None
        self._sources = []

    # ───────────────────────────────────────────────────────────
    #  INGESTION BACKENDS
    # ───────────────────────────────────────────────────────────

    def _tail_file(self, filepath: str):
        """Continuously tail a file like 'tail -f'."""
        try:
            with open(filepath, 'r', errors='ignore') as f:
                f.seek(0, 2)
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.05)
                        continue
                    self.event_queue.put(line.strip())
        except Exception as e:
            self.event_queue.put(f"ERROR: File tail failed — {e}")

    def _start_syslog_server(self, host: str, port: int):
        """Start UDP Syslog receiver."""
        try:
            self._server = socketserver.UDPServer((host, port), SyslogUDPHandler)
            self._server.event_queue = self.event_queue
            self._server.serve_forever()
        except PermissionError:
            self.event_queue.put(f"ERROR: Port {port} requires admin privileges. Try a port > 1024.")
        except Exception as e:
            self.event_queue.put(f"ERROR: Syslog server failed — {e}")

    # ───────────────────────────────────────────────────────────
    #  DASHBOARD RENDERING
    # ───────────────────────────────────────────────────────────

    def _make_header(self) -> Panel:
        """Top header bar with uptime and source info."""
        elapsed = ""
        if self.stats["start_time"]:
            delta = datetime.now() - self.stats["start_time"]
            m, s = divmod(int(delta.total_seconds()), 60)
            elapsed = f"{m:02d}:{s:02d}"

        sources_str = " | ".join(self._sources) if self._sources else "None"
        header = Text()
        header.append("  🛡️  LogSentinel Pro", style="bold cyan")
        header.append("  —  ", style="dim")
        header.append("LIVE THREAT DASHBOARD", style="bold white")
        header.append(f"    ⏱ {elapsed}  ", style="dim green")
        header.append(f"  Sources: {sources_str}", style="dim")
        return Panel(header, style="cyan", height=3)

    def _make_metrics(self) -> Panel:
        """Left sidebar with scores, stats, and severity counts."""
        
        # Handle both v3 and v4 analyzer APIs
        if hasattr(self.analyzer, "summary"):
            summary = self.analyzer.summary()
            score = summary.get("score", 0)
            level = summary.get("level", "LOW")
        else:
            # Fallback calculation if analyzer lacks summary()
            if self.severity_counts["CRITICAL"] > 0:
                score = min(100, 75 + (self.severity_counts["CRITICAL"] * 5))
                level = "CRITICAL"
            elif self.severity_counts["HIGH"] > 0:
                score = min(80, 50 + (self.severity_counts["HIGH"] * 5))
                level = "HIGH"
            elif self.severity_counts["MEDIUM"] > 0:
                score = min(60, 25 + (self.severity_counts["MEDIUM"] * 2))
                level = "MEDIUM"
            else:
                score = min(30, self.severity_counts["LOW"])
                level = "LOW"

        colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}
        c = colors.get(level, "white")

        bar_len = 20
        filled = min(bar_len, int((score / 100.0) * bar_len))
        bar = ("█" * filled) + ("░" * (bar_len - filled))

        content = (
            f"\n [bold]THREAT LEVEL[/bold]\n"
            f" [{c}]{bar}[/{c}]\n"
            f" [bold {c}]{level}  {score}/100[/bold {c}]\n"
            f"\n"
            f" [bold]STATISTICS[/bold]\n"
            f" Events In     [cyan]{self.stats['events_processed']:>6,}[/cyan]\n"
            f" Parsed        [cyan]{self.stats['events_parsed']:>6,}[/cyan]\n"
            f" Threats       [red]{self.stats['threats_detected']:>6,}[/red]\n"
            f"\n"
            f" [bold]SEVERITY[/bold]\n"
            f" [red]● CRITICAL     {self.severity_counts.get('CRITICAL', 0):>4}[/red]\n"
            f" [yellow]● HIGH         {self.severity_counts.get('HIGH', 0):>4}[/yellow]\n"
            f" [blue]● MEDIUM       {self.severity_counts.get('MEDIUM', 0):>4}[/blue]\n"
            f" [green]● LOW          {self.severity_counts.get('LOW', 0):>4}[/green]\n"
        )

        # Top attacker IPs
        if self.source_ips:
            content += "\n [bold]TOP ATTACKERS[/bold]\n"
            sorted_ips = sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            for ip, count in sorted_ips:
                content += f" [red]{ip:<16}[/red] [bold]{count:>3}[/bold]\n"

        # Attack type breakdown
        if self.attack_types:
            content += "\n [bold]ATTACK TYPES[/bold]\n"
            sorted_types = sorted(self.attack_types.items(), key=lambda x: x[1], reverse=True)[:6]
            for atype, count in sorted_types:
                label = atype.replace("_", " ").title()[:18]
                content += f" [magenta]{label:<18}[/magenta] [bold]{count:>3}[/bold]\n"

        return Panel(content, title="📊 Metrics", border_style="cyan", box=ROUNDED)

    def _make_live_logs(self) -> Panel:
        """Raw log stream panel — threats highlighted in RED, normal in green."""
        log_text = Text()

        display_logs = self.recent_logs[-25:]
        if not display_logs:
            log_text.append("  Waiting for incoming log events...\n", style="dim")
        else:
            for entry in display_logs:
                ts = entry["time"]
                raw = entry["raw"][:120]
                is_threat = entry.get("is_threat", False)

                if is_threat:
                    log_text.append(f"  {ts} ", style="dim red")
                    log_text.append("▶ ", style="bold red")
                    log_text.append(f"{raw}\n", style="bold red")
                else:
                    log_text.append(f"  {ts} ", style="dim green")
                    log_text.append("▶ ", style="green")
                    log_text.append(f"{raw}\n", style="green")

        return Panel(log_text, title="📜 Live Log Stream (threats in RED)", border_style="green", box=ROUNDED)

    def _make_threat_table(self) -> Panel:
        """Detected threats table with MITRE IDs."""
        table = Table(box=ROUNDED, expand=True, show_lines=False)
        table.add_column("TIME", style="dim cyan", width=10, no_wrap=True)
        table.add_column("SEV", width=10, no_wrap=True)
        table.add_column("TYPE", style="bold", width=22, no_wrap=True)
        table.add_column("MITRE", style="magenta", width=12, no_wrap=True)
        table.add_column("DETAILS", ratio=1)

        colors = {"CRITICAL": "bold red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}

        display_threats = list(reversed(self.recent_threats[-15:]))
        if not display_threats:
            table.add_row("—", "—", "[dim]Waiting for threats...[/dim]", "—", "—")
        else:
            for t in display_threats:
                sev = t.get("severity", "LOW")
                sc = colors.get(sev, "white")
                ts = t.get("timestamp", "")
                if len(ts) > 8:
                    ts = ts[-8:]
                mitre = t.get("mitre", "—")
                ttype = t.get("type", "UNKNOWN").replace("_", " ")
                detail = t.get("match", "")[:45]
                table.add_row(ts, f"[{sc}]{sev}[/{sc}]", ttype, mitre, detail)

        return Panel(table, title="🚨 Detected Threats", border_style="red", box=ROUNDED)

    def _make_footer(self) -> Panel:
        """Bottom status bar."""
        footer = Text()
        footer.append("  MODE: ", style="dim")
        footer.append("● LIVE", style="bold green")
        footer.append("  │  ", style="dim")
        footer.append("Ctrl+C", style="bold yellow")
        footer.append(" to stop  │  ", style="dim")
        footer.append(f"EPS: ~{self._calc_eps():.1f}", style="dim cyan")
        footer.append("  │  ", style="dim")
        footer.append(f"🔴 {self.severity_counts.get('CRITICAL',0)} CRIT", style="bold red")
        footer.append(f"  🟡 {self.severity_counts.get('HIGH',0)} HIGH", style="yellow")
        footer.append(f"  🔵 {self.severity_counts.get('MEDIUM',0)} MED", style="blue")
        return Panel(footer, height=3)

    def _calc_eps(self) -> float:
        """Events per second."""
        if not self.stats["start_time"]:
            return 0.0
        elapsed = (datetime.now() - self.stats["start_time"]).total_seconds()
        if elapsed < 1:
            return 0.0
        return self.stats["events_processed"] / elapsed

    def generate_dashboard(self) -> Layout:
        """Assemble the full 4-panel dashboard."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )

        # Body: left metrics sidebar + right content area
        layout["body"].split_row(
            Layout(name="sidebar", ratio=1, minimum_size=32),
            Layout(name="content", ratio=3),
        )

        # Content: live logs on top, threat table below
        layout["content"].split_column(
            Layout(name="live_logs", ratio=1),
            Layout(name="threats", ratio=1),
        )

        # Populate everything
        layout["header"].update(self._make_header())
        layout["sidebar"].update(self._make_metrics())
        layout["live_logs"].update(self._make_live_logs())
        layout["threats"].update(self._make_threat_table())
        layout["footer"].update(self._make_footer())

        return layout

    # ───────────────────────────────────────────────────────────
    #  EVENT PROCESSING
    # ───────────────────────────────────────────────────────────

    def _process_line(self, line: str):
        """Parse a raw log line, detect threats, update stats."""
        self.stats["events_processed"] += 1
        is_threat = False

        event = self.parser.parse(line)
        if event:
            self.stats["events_parsed"] += 1

            # Run through ThreatAnalyzer.process() → calls LogParser.detect() internally
            threats = self.analyzer.process(event)

            if threats:
                is_threat = True
                self.stats["threats_detected"] += len(threats)
                for t in threats:
                    self.severity_counts[t.get("severity", "LOW")] += 1
                    self.attack_types[t.get("type", "UNKNOWN")] += 1

                    # Extract attacker IP from the raw message
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', event.get("message", ""))
                    if ip_match:
                        attacker_ip = ip_match.group(0)
                        self.source_ips[attacker_ip] += 1

                    # Send Telegram alert for CRITICAL/HIGH threats (rate-limited)
                    if TELEGRAM_ALERTER:
                        try:
                            TELEGRAM_ALERTER.send_threat_alert(t)
                        except Exception:
                            pass

                self.recent_threats.extend(threats)

        # Store raw log with threat flag for the live log panel
        self.recent_logs.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "raw": line,
            "is_threat": is_threat,
        })

        # Cap histories
        if len(self.recent_threats) > 100:
            self.recent_threats = self.recent_threats[-100:]
        if len(self.recent_logs) > 60:
            self.recent_logs = self.recent_logs[-60:]

    # ───────────────────────────────────────────────────────────
    #  MAIN ENTRY POINT
    # ───────────────────────────────────────────────────────────

    def start(self, tail_file: Optional[str] = None, listen_host: str = "0.0.0.0", listen_port: int = 5144):
        """Start the full live monitoring system."""
        self.running = True
        self.stats["start_time"] = datetime.now()

        # 1. Start file tailer
        if tail_file and os.path.exists(tail_file):
            self._sources.append(f"FILE: {os.path.basename(tail_file)}")
            t = threading.Thread(target=self._tail_file, args=(tail_file,), daemon=True)
            self.threads.append(t)
            t.start()

        # 2. Start network listener
        if listen_port and listen_port > 0:
            self._sources.append(f"UDP: {listen_host}:{listen_port}")
            t = threading.Thread(target=self._start_syslog_server, args=(listen_host, listen_port), daemon=True)
            self.threads.append(t)
            t.start()

        if not self._sources:
            console.print("[red]No ingestion source specified. Use -f for file or -p for syslog port.[/red]")
            return

        # 3. Dashboard event loop
        try:
            with Live(self.generate_dashboard(), refresh_per_second=4, screen=False) as live:
                while self.running:
                    processed_any = False
                    # Drain the queue in small batches
                    for _ in range(50):
                        try:
                            line = self.event_queue.get_nowait()
                            if line.startswith("ERROR:"):
                                self.recent_threats.append({
                                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                                    "severity": "HIGH",
                                    "type": "SYSTEM_ERROR",
                                    "mitre": "—",
                                    "match": line[7:]
                                })
                                self.recent_logs.append({
                                    "time": datetime.now().strftime("%H:%M:%S"),
                                    "raw": line,
                                    "is_threat": True,
                                })
                                self.severity_counts["HIGH"] += 1
                                self.stats["threats_detected"] += 1
                                processed_any = True
                                continue

                            self._process_line(line)
                            processed_any = True
                        except queue.Empty:
                            break

                    # Always refresh the dashboard
                    live.update(self.generate_dashboard())

                    if not processed_any:
                        time.sleep(0.15)

        except KeyboardInterrupt:
            self.running = False
            if self._server:
                self._server.shutdown()
            console.print("\n[bold green]✓ Live monitoring stopped safely.[/bold green]")
            console.print(f"[dim]  Events processed: {self.stats['events_processed']:,}[/dim]")
            console.print(f"[dim]  Threats detected: {self.stats['threats_detected']:,}[/dim]")
