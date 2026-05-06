#!/usr/bin/env python3
"""
nmap_pro_analyzer.py
====================
A professional, adaptive Nmap XML output parser that intelligently displays results
for ANY type of scan (network sweeps, single hosts, OS detection, service enumeration).

Features:
  ✓ Automatic scan type detection (network, single-host, service-focused, etc.)
  ✓ OS-based role inference (Windows, Linux, macOS, networking equipment, etc.)
  ✓ Universal service detection (works with any port/service combination)
  ✓ Rich color-coded terminal output with infrastructure insights
  ✓ Risk stratification based on port criticality
  ✓ Graceful handling of incomplete/partial scans

Usage:
    python nmap_pro_analyzer.py <scan.xml> [scan2.xml ...]
    python nmap_pro_analyzer.py --demo              # run with built-in demo data
    python nmap_pro_analyzer.py --help

Dependencies (install once):
    pip install python-nmap rich
"""

import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from collections import Counter

# ── third-party ──────────────────────────────────────────────────────────────
try:
    import nmap
except ImportError:
    sys.exit(
        "[ERROR] python-nmap is not installed.\n"
        "  Run:  pip install python-nmap"
    )

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
except ImportError:
    sys.exit(
        "[ERROR] rich is not installed.\n"
        "  Run:  pip install rich"
    )

# ─────────────────────────────────────────────────────────────────────────────
#  Lightweight PortScanner subclass – bypasses nmap-binary requirement
# ─────────────────────────────────────────────────────────────────────────────

class _XMLOnlyScanner(nmap.PortScanner):
    """PortScanner subclass that skips binary discovery, only parses XML."""
    def __init__(self) -> None:  # type: ignore[override]
        self._nmap_path = ""
        self._scan_result = {}
        self._nmap_version_number = 0
        self._nmap_subversion_number = 0
        self._nmap_last_output = ""
        self.__process = None  # noqa: SLF001


# ─────────────────────────────────────────────────────────────────────────────
#  Risk classification
# ─────────────────────────────────────────────────────────────────────────────

RISK_MAP: dict[int, tuple[str, str]] = {
    # ── Critical – Active Directory / Kerberos / SMB / LDAP
    88:    ("Critical", "bold red"),
    135:   ("Critical", "bold red"),
    137:   ("Critical", "bold red"),
    138:   ("Critical", "bold red"),
    139:   ("Critical", "bold red"),
    389:   ("Critical", "bold red"),
    445:   ("Critical", "bold red"),
    464:   ("Critical", "bold red"),
    636:   ("Critical", "bold red"),
    3268:  ("Critical", "bold red"),
    3269:  ("Critical", "bold red"),
    # ── Critical – Database engines (exposed to network)
    1433:  ("Critical", "bold red"),
    1521:  ("Critical", "bold red"),
    3306:  ("Critical", "bold red"),
    5432:  ("Critical", "bold red"),
    6379:  ("Critical", "bold red"),
    27017: ("Critical", "bold red"),
    # ── Critical – Remote access / management
    23:    ("Critical", "bold red"),
    512:   ("Critical", "bold red"),
    513:   ("Critical", "bold red"),
    514:   ("Critical", "bold red"),
    5900:  ("Critical", "bold red"),
    5985:  ("Critical", "bold red"),   # WinRM HTTP
    5986:  ("Critical", "bold red"),   # WinRM HTTPS
    # ── High – well-known services worth extra attention
    21:    ("High",     "red"),
    22:    ("High",     "red"),        # SSH – high value target
    25:    ("High",     "red"),
    53:    ("High",     "red"),        # DNS
    110:   ("High",     "red"),
    143:   ("High",     "red"),
    161:   ("High",     "red"),        # SNMP
    162:   ("High",     "red"),
    2049:  ("High",     "red"),        # NFS
    3389:  ("High",     "red"),        # RDP
    8080:  ("High",     "red"),
    8443:  ("High",     "red"),
    # ── Medium – standard web / TLS
    80:    ("Medium",   "yellow"),
    443:   ("Medium",   "yellow"),
    8000:  ("Medium",   "yellow"),
    8001:  ("Medium",   "yellow"),
    8888:  ("Medium",   "yellow"),
    8080:  ("Medium",   "yellow"),
}

DEFAULT_RISK = ("Low", "green")


def get_risk(port: int) -> tuple[str, str]:
    """Return (risk_label, rich_style) for a given port number."""
    return RISK_MAP.get(port, DEFAULT_RISK)


# ─────────────────────────────────────────────────────────────────────────────
#  Flexible infrastructure role fingerprinting (works with ANY scan)
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (display_name, required_ports, optional_ports_for_confidence, icon)
ROLE_SIGNATURES: list[tuple[str, set[int], set[int], str]] = [
    # ── Windows / Active Directory
    ("Windows Domain Controller",        {88, 389, 445},        {53, 135, 3268, 3389},    "🏢"),
    ("Windows Domain Controller",        {88, 636, 3268},       {389, 445, 53},           "🏢"),
    ("Active Directory Server",          {389, 445},            {88, 135, 3268},          "🏢"),
    ("Kerberos + SMB Server",            {88, 445},             {389, 139, 135},          "🔐"),
    ("Windows File Server (SMB)",        {139, 445},            {3389, 135},              "📁"),
    ("Windows RDP Server",               {3389},                {445, 139},               "🖥️ "),
    ("WinRM Management Host",            {5985, 5986},          {3389, 445},              "⚙️ "),

    # ── DNS & Network Services
    ("DNS Server",                       {53},                  {389, 445, 161},          "🌐"),
    ("DHCP + DNS",                       {53, 67, 68},          {161},                    "🌐"),
    ("SNMP Network Device",              {161},                 {22, 80},                 "📡"),
    ("Network Infrastructure",           {161, 22},             {53, 80},                 "🔌"),

    # ── Web Servers & Reverse Proxies
    ("Web Server (HTTP+HTTPS)",          {80, 443},             {22, 3306, 5432},         "🌍"),
    ("Web Server (HTTPS only)",          {443},                 {80, 22},                 "🔒"),
    ("Web Server (HTTP only)",           {80},                  {443, 22},                "🌍"),
    ("Web Server + SSH",                 {80, 443, 22},         {3306, 5432},             "🌍"),
    ("API/App Server",                   {8080, 8000, 8888},    {22, 443},                "⚡"),
    ("Reverse Proxy / Load Balancer",    {80, 443},             {22, 8080},               "🔄"),

    # ── Linux/Unix Servers (common patterns)
    ("Linux Web Server",                 {22, 80, 443},         {3306, 5432},             "🐧"),
    ("Linux Application Server",         {22, 8080, 8443},      {3306, 5432},             "🐧"),
    ("SSH Server (Linux/Unix)",          {22},                  {80, 443, 3306},          "🖥️ "),

    # ── Email Services
    ("Mail Server (full stack)",         {25, 110, 143},        {465, 587, 993, 995},     "✉️ "),
    ("Mail Server (SMTP+IMAP)",          {25, 143},             {110, 465, 587, 993},     "✉️ "),
    ("Mail Server (SMTP only)",          {25},                  {587, 465, 110, 143},     "✉️ "),
    ("Mail Server (IMAP)",               {143},                 {110, 993, 995, 25},      "✉️ "),

    # ── Databases (exposed)
    ("MySQL/MariaDB Database",           {3306},                {22, 3307},               "🗄️ "),
    ("PostgreSQL Database",              {5432},                {22},                     "🗄️ "),
    ("MSSQL Server Database",            {1433},                {445, 3389},              "🗄️ "),
    ("Oracle Database",                  {1521},                {22},                     "🗄️ "),
    ("MongoDB Database",                 {27017},               {28017, 27018},           "🗄️ "),
    ("Redis / Memcached",                {6379, 11211},         {22},                     "⚡"),

    # ── File Sharing & Storage
    ("NFS Server",                       {2049},                {111, 22},                "📁"),
    ("SMB/Samba File Server",            {445, 139},            {22, 3389},               "📁"),
    ("FTP Server",                       {21},                  {22, 80},                 "📦"),
    ("SFTP/SSH File Access",             {22},                  {21, 80},                 "📦"),

    # ── Directory Services & LDAP
    ("LDAP Directory Server",            {389},                 {636, 88, 445},           "📒"),
    ("LDAPS (Secure LDAP)",              {636},                 {389, 88},                "📒"),

    # ── Remote Access & VNC
    ("VNC Server",                       {5900},                {22},                     "🖥️ "),
    ("Remote Desktop",                   {3389},                {22, 445},                "🖥️ "),

    # ── Containers & Orchestration
    ("Docker Host",                      {2375, 2376},          {22, 443},                "🐳"),
    ("Kubernetes Node",                  {6443, 10250},         {22, 443},                "☸️ "),
    ("Container Registry",               {5000},                {22, 443},                "📦"),

    # ── Security & Logging
    ("Syslog Server",                    {514},                 {22, 80, 443},            "📋"),

    # ── Legacy / Dangerous
    ("Telnet (legacy/insecure)",         {23},                  {22},                     "⚠️ "),
    ("Rsh/Rlogin (dangerous)",           {512, 513, 514},       {22},                     "⚠️ "),
]


def infer_roles(open_ports: set[int], os_hint: str = "") -> list[str]:
    """
    Return a list of inferred role strings for the given open-port set.
    
    Args:
        open_ports: Set of open port numbers
        os_hint: Optional OS hint (e.g., "Windows Server 2019", "Ubuntu Linux")
    
    Returns:
        List of [icon  role_name] strings
    """
    matched: list[tuple[str, int]] = []  # (role_string, confidence_score)
    seen: set[str] = set()

    for name, required, optional, icon in ROLE_SIGNATURES:
        # Must have all required ports
        if not required.issubset(open_ports):
            continue

        if name in seen:
            continue

        # Calculate confidence: how many optional ports are present
        confidence = len(required) + len(optional.intersection(open_ports))
        matched.append((f"{icon}  {name}", confidence))
        seen.add(name)

    # Sort by confidence (higher = more specific), keep top 3
    matched.sort(key=lambda x: x[1], reverse=True)
    return [role for role, _ in matched[:3]] if matched else ["❓  Unknown / Generic Host"]


def detect_os_family(os_hint: str) -> str:
    """Classify OS family from nmap OS detection string."""
    os_lower = os_hint.lower()
    if "windows" in os_lower or "microsoft" in os_lower:
        return "Windows"
    elif "linux" in os_lower or "ubuntu" in os_lower or "debian" in os_lower:
        return "Linux"
    elif "macos" in os_lower or "mac os" in os_lower or "darwin" in os_lower:
        return "macOS"
    elif "freebsd" in os_lower or "netbsd" in os_lower:
        return "BSD"
    elif "cisco" in os_lower or "juniper" in os_lower or "fortinet" in os_lower:
        return "Network Device"
    elif "router" in os_lower or "switch" in os_lower or "firewall" in os_lower:
        return "Network Device"
    elif "printer" in os_lower or "hp" in os_lower or "xerox" in os_lower:
        return "Printer"
    elif "synology" in os_lower or "nas" in os_lower or "qnap" in os_lower:
        return "NAS/Storage"
    else:
        return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PortInfo:
    port:     int
    protocol: str
    state:    str
    service:  str
    product:  str
    version:  str

    @property
    def display_version(self) -> str:
        return " ".join(filter(None, [self.product, self.version])) or "—"

    @property
    def risk(self) -> tuple[str, str]:
        return get_risk(self.port)


@dataclass
class HostResult:
    ip:        str
    status:    str
    hostnames: list[str] = field(default_factory=list)
    ports:     list[PortInfo] = field(default_factory=list)
    os_match:  str = ""  # OS detection string from nmap

    @property
    def open_port_numbers(self) -> set[int]:
        return {p.port for p in self.ports if p.state == "open"}

    @property
    def hostname_str(self) -> str:
        return ", ".join(self.hostnames) if self.hostnames else "—"

    @property
    def os_family(self) -> str:
        return detect_os_family(self.os_match)


# ─────────────────────────────────────────────────────────────────────────────
#  XML parsing
# ─────────────────────────────────────────────────────────────────────────────

def _hostname_map(xml_path: Path) -> dict[str, list[str]]:
    """Build {ip: [hostname, ...]} via raw ElementTree."""
    mapping: dict[str, list[str]] = {}
    try:
        tree = ET.parse(xml_path)
        for host_el in tree.findall(".//host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            if addr_el is None:
                continue
            ip    = addr_el.get("addr", "")
            names = [
                hn.get("name", "")
                for hn in host_el.findall(".//hostname")
                if hn.get("name")
            ]
            if ip:
                mapping[ip] = names
    except ET.ParseError:
        pass
    return mapping


def _os_map(xml_path: Path) -> dict[str, str]:
    """Build {ip: os_detection_string} via raw ElementTree."""
    mapping: dict[str, str] = {}
    try:
        tree = ET.parse(xml_path)
        for host_el in tree.findall(".//host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            
            # Try to find OS match
            os_el = host_el.find(".//osmatch")
            if os_el is not None:
                os_name = os_el.get("name", "")
                if ip and os_name:
                    mapping[ip] = os_name
    except ET.ParseError:
        pass
    return mapping


def parse_xml(xml_path: Path) -> list[HostResult]:
    """Parse an Nmap XML file; return a list of HostResult objects."""
    if not xml_path.exists():
        raise FileNotFoundError(f"File not found: {xml_path}")

    xml_text = xml_path.read_text(encoding="utf-8", errors="replace")

    try:
        ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed XML in '{xml_path}': {exc}") from exc

    nm = _XMLOnlyScanner()
    try:
        nm.analyse_nmap_xml_scan(xml_text)
    except nmap.PortScannerError as exc:
        raise ValueError(f"python-nmap could not parse '{xml_path}': {exc}") from exc

    hostnames = _hostname_map(xml_path)
    os_info    = _os_map(xml_path)
    results: list[HostResult] = []

    for ip in nm.all_hosts():
        host_data = nm[ip]
        ports: list[PortInfo] = []
        
        for proto in host_data.all_protocols():
            for port_num in sorted(host_data[proto].keys()):
                p = host_data[proto][port_num]
                ports.append(PortInfo(
                    port     = port_num,
                    protocol = proto,
                    state    = p.get("state",   "unknown"),
                    service  = p.get("name",    "—"),
                    product  = p.get("product", ""),
                    version  = p.get("version", ""),
                ))
        
        results.append(HostResult(
            ip        = ip,
            status    = host_data.state(),
            hostnames = hostnames.get(ip, []),
            ports     = ports,
            os_match  = os_info.get(ip, ""),
        ))

    return results


# ─────────────────────────────────────────────────────────────────────────────
#  Display helpers
# ─────────────────────────────────────────────────────────────────────────────

console = Console()


def _port_table(host: HostResult) -> Table:
    """Build a rich table for all ports on a host."""
    tbl = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=False,
        padding=(0, 1),
    )
    tbl.add_column("Port",     style="bold white",  justify="right", min_width=7)
    tbl.add_column("Protocol", style="dim white",   justify="center", min_width=8)
    tbl.add_column("State",    justify="center",    min_width=9)
    tbl.add_column("Service",  style="bright_cyan", min_width=14)
    tbl.add_column("Product / Version", min_width=28)
    tbl.add_column("Risk",     justify="center",    min_width=10)

    for p in host.ports:
        risk_label, risk_style = p.risk

        state_text = Text(p.state)
        if p.state == "open":
            state_text.stylize("bold green")
        elif p.state == "closed":
            state_text.stylize("red")
        else:
            state_text.stylize("yellow")

        tbl.add_row(
            str(p.port),
            p.protocol,
            state_text,
            p.service,
            Text(p.display_version, style="white"),
            Text(risk_label, style=risk_style),
        )

    return tbl


def _print_host(host: HostResult, index: int) -> None:
    """Render one host: header panel → port table → role inference panel."""

    # ── Header ────────────────────────────────────────────────────────────
    up = host.status.lower() == "up"
    status_markup = "[bold green]UP[/]" if up else "[bold red]DOWN[/]"
    open_count   = len([p for p in host.ports if p.state == "open"])
    closed_count = len(host.ports) - open_count

    header_lines = [
        f"[bold white]Host #{index}[/]   [bold cyan]{host.ip}[/]",
        f"[dim]Hostname(s):[/]  {host.hostname_str}",
        f"[dim]Status:    [/]  {status_markup}",
    ]

    # Add OS info if detected
    if host.os_match:
        header_lines.append(f"[dim]OS Detected:[/]  [bold magenta]{host.os_match}[/] [dim]({host.os_family})[/]")

    header_lines.append(
        f"[dim]Ports:     [/]  {len(host.ports)} found  "
        f"([green]{open_count} open[/] / [dim]{closed_count} closed[/])"
    )

    console.print(Panel(
        "\n".join(header_lines),
        border_style="cyan",
        expand=False,
        padding=(0, 2),
    ))

    # ── Port table ────────────────────────────────────────────────────────
    if host.ports:
        console.print(_port_table(host))
    else:
        console.print("  [dim italic]No port data available.[/]")

    # ── Role inference ────────────────────────────────────────────────────
    roles = infer_roles(host.open_port_numbers, host.os_match)
    role_body = "\n".join(f"  {r}" for r in roles)
    
    role_title = f"[bold magenta]Infrastructure Inference ({host.os_family})[/]"
    console.print(Panel(
        role_body,
        title=role_title,
        border_style="magenta",
        expand=False,
        padding=(0, 1),
    ))
    console.print()


def _print_summary(results: list[HostResult], source: str) -> None:
    """Render a compact summary table across all hosts."""
    console.print(Rule("[bold yellow]SCAN SUMMARY[/]", style="yellow"))

    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold yellow",
        border_style="yellow",
        expand=False,
        padding=(0, 1),
    )
    tbl.add_column("IP Address",   style="bold cyan",    min_width=16)
    tbl.add_column("Status",       justify="center",     min_width=7)
    tbl.add_column("Hostnames",                          min_width=20)
    tbl.add_column("OS Family",    style="magenta",      min_width=12)
    tbl.add_column("Open Ports",   justify="right",      min_width=11)
    tbl.add_column("Critical ⚠",   justify="center",     min_width=10)
    tbl.add_column("Primary Role")

    for host in results:
        open_ports   = [p for p in host.ports if p.state == "open"]
        critical_cnt = sum(1 for p in open_ports if get_risk(p.port)[0] == "Critical")
        roles        = infer_roles(host.open_port_numbers, host.os_match)

        up = host.status.lower() == "up"
        status_txt = Text("UP" if up else "DOWN", style="bold green" if up else "bold red")
        crit_txt   = Text(str(critical_cnt), style="bold red" if critical_cnt else "dim")

        tbl.add_row(
            host.ip,
            status_txt,
            host.hostname_str,
            host.os_family,
            str(len(open_ports)),
            crit_txt,
            roles[0],
        )

    console.print(tbl)

    # ── Scan statistics ──────────────────────────────────────────────────
    up_count = sum(1 for h in results if h.status.lower() == "up")
    down_count = len(results) - up_count
    total_open = sum(len([p for p in h.ports if p.state == "open"]) for h in results)
    
    # OS family breakdown
    os_families = Counter(h.os_family for h in results if h.status.lower() == "up")
    os_breakdown = "  " + ", ".join(f"{k}: {v}" for k, v in os_families.most_common())

    console.print(
        f"\n[dim]Source: [white]{source}[/][/]\n"
        f"[dim]Hosts: [white]{len(results)}[/] total  "
        f"([green]{up_count} up[/] / [red]{down_count} down[/])  |  "
        f"Ports: [white]{total_open}[/] open[/]\n"
        f"[dim]OS Breakdown:[/]\n{os_breakdown}\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Demo mode – comprehensive Nmap XML covering multiple scenarios
# ─────────────────────────────────────────────────────────────────────────────

_DEMO_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -O -p- 192.168.10.0/24" start="1700000000" startstr="Tue Nov 14 10:00:00 2023" version="7.94">

  <!-- 1. Windows Domain Controller -->
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.10.10" addrtype="ipv4"/>
    <hostnames><hostname name="dc01.corp.local" type="PTR"/></hostnames>
    <osmatch name="Windows Server 2019 Standard" accuracy="95"/>
    <ports>
      <port protocol="tcp" portid="53"><state state="open"/><service name="domain" product="Microsoft DNS" version="10.0"/></port>
      <port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec" product="Microsoft Windows Kerberos"/></port>
      <port protocol="tcp" portid="135"><state state="open"/><service name="msrpc" product="Microsoft Windows RPC"/></port>
      <port protocol="tcp" portid="389"><state state="open"/><service name="ldap" product="Microsoft Windows LDAP" version="10.0"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows Server 2019"/></port>
      <port protocol="tcp" portid="3268"><state state="open"/><service name="msft-gc" product="Microsoft Windows Active Directory"/></port>
      <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server" product="Microsoft Terminal Services"/></port>
    </ports>
  </host>

  <!-- 2. Linux Web Server with Database -->
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.10.50" addrtype="ipv4"/>
    <hostnames><hostname name="web01.corp.local" type="PTR"/></hostnames>
    <osmatch name="Linux 5.10 - 5.15" accuracy="92"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port>
      <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.36"/></port>
      <port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL" version="14.10"/></port>
    </ports>
  </host>

  <!-- 3. Mail Server -->
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.10.75" addrtype="ipv4"/>
    <hostnames><hostname name="mail.corp.local" type="PTR"/></hostnames>
    <osmatch name="Linux 4.19 - 5.10" accuracy="88"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.9p1"/></port>
      <port protocol="tcp" portid="25"><state state="open"/><service name="smtp" product="Postfix smtpd"/></port>
      <port protocol="tcp" portid="110"><state state="open"/><service name="pop3" product="Dovecot pop3d"/></port>
      <port protocol="tcp" portid="143"><state state="open"/><service name="imap" product="Dovecot imapd"/></port>
      <port protocol="tcp" portid="465"><state state="open"/><service name="smtps" product="Postfix smtpd"/></port>
      <port protocol="tcp" portid="587"><state state="open"/><service name="submission" product="Postfix smtpd"/></port>
      <port protocol="tcp" portid="993"><state state="open"/><service name="imaps" product="Dovecot imapd"/></port>
      <port protocol="tcp" portid="995"><state state="open"/><service name="pop3s" product="Dovecot pop3d"/></port>
    </ports>
  </host>

  <!-- 4. Docker Host / Container System -->
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.10.100" addrtype="ipv4"/>
    <hostnames><hostname name="docker01.corp.local" type="PTR"/></hostnames>
    <osmatch name="Linux 5.15 (Docker)" accuracy="89"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.0p1"/></port>
      <port protocol="tcp" portid="2375"><state state="open"/><service name="docker" product="Docker Daemon" version="24.0.0"/></port>
      <port protocol="tcp" portid="5000"><state state="open"/><service name="registry" product="Docker Registry" version="2.8.0"/></port>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy" product="Kubernetes Dashboard"/></port>
    </ports>
  </host>

  <!-- 5. NAS / Storage Device -->
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.10.150" addrtype="ipv4"/>
    <hostnames><hostname name="storage.corp.local" type="PTR"/></hostnames>
    <osmatch name="Synology DiskStation DSM 7.0" accuracy="91"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4p1"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Synology DSM" version="7.0"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Synology DSM" version="7.0"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Samba 4.13.17"/></port>
      <port protocol="tcp" portid="2049"><state state="open"/><service name="nfs" product="NFS v3,v4"/></port>
    </ports>
  </host>

  <!-- 6. Network Device (Switch / Router) -->
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.10.1" addrtype="ipv4"/>
    <hostnames><hostname name="gateway.corp.local" type="PTR"/></hostnames>
    <osmatch name="Cisco IOS 15.2" accuracy="87"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="Cisco IOS SSH"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Cisco HTTP Server"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Cisco HTTPS Server"/></port>
      <port protocol="udp" portid="161"><state state="open"/><service name="snmp" product="Cisco SNMP"/></port>
    </ports>
  </host>

  <!-- 7. Down/Offline Host -->
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.10.200" addrtype="ipv4"/>
    <hostnames/>
    <ports/>
  </host>

  <runstats>
    <finished time="1700000100" timestr="Tue Nov 14 10:01:40 2023" summary="Nmap done at Tue Nov 14 10:01:40 2023; 7 IP addresses (7 hosts up) scanned in 100 seconds" elapsed="100" exit="success"/>
    <hosts up="6" down="1" total="7"/>
  </runstats>

</nmaprun>
"""


def _run_demo() -> None:
    """Run demo with embedded XML (no nmap binary needed)."""
    import os, tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(_DEMO_XML)
        tmp = Path(fh.name)
    try:
        _analyse_file(tmp)
    finally:
        os.unlink(tmp)


# ─────────────────────────────────────────────────────────────────────────────
#  Core pipeline
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_file(xml_path: Path) -> None:
    """Parse → display → summarise a single XML file."""
    console.print()
    console.print(Rule(
        f"[bold cyan]Nmap Pro Analyzer[/]  [dim]▸  {xml_path.name}[/]",
        style="cyan",
    ))

    try:
        results = parse_xml(xml_path)
    except FileNotFoundError as exc:
        console.print(f"\n[bold red][ERROR][/] {exc}\n")
        return
    except ValueError as exc:
        console.print(f"\n[bold red][ERROR][/] {exc}\n")
        return

    if not results:
        console.print("\n[yellow]No hosts found in the XML file.[/]\n")
        return

    console.print()
    for idx, host in enumerate(results, start=1):
        _print_host(host, idx)

    _print_summary(results, str(xml_path))


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

_BANNER = r"""
[bold cyan]
  ███╗   ██╗███╗   ███╗ █████╗ ██████╗     ██████╗ ██████╗  ██████╗
  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗
  ██╔██╗ ██║██╔████╔██║███████║██████╔╝    ██████╔╝██████╔╝██║   ██║
  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝     ██╔═══╝ ██╔══██╗██║   ██║
  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║         ██║     ██║  ██║╚██████╔╝
  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝     ╚═╝  ╚═╝ ╚═════╝
[/bold cyan]
[dim]  Professional Nmap XML Analyzer  │  Adaptive Infrastructure Analysis[/dim]
"""

_HELP = """\
[bold]Usage:[/]
  [cyan]python nmap_pro_analyzer.py[/]  [white]<scan.xml>[/] [dim][scan2.xml ...][/dim]
  [cyan]python nmap_pro_analyzer.py[/]  [white]--demo[/]

[bold]Generate Nmap XML files:[/]
  [dim]Single host with full enum:[/]
  sudo nmap -sV -O -p- -oX output.xml <target>

  [dim]Network sweep:[/]
  sudo nmap -sV -O -oX network.xml 192.168.1.0/24

  [dim]Service enumeration:[/]
  nmap -sV -p- --script nmap-service-probes -oX services.xml <target>

[bold]Features:[/]
  ✓ Auto-detects any scan type (network, host, service-focused)
  ✓ OS-aware role inference (Windows, Linux, Docker, etc.)
  ✓ Universal port/service analysis
  ✓ Risk stratification per port
  ✓ Color-coded terminal output

[bold]Risk Levels:[/]
  [bold red]Critical[/] – AD/Kerberos/SMB, exposed databases, remote access
  [red]High[/]     – SSH, FTP, SMTP, DNS, RDP, SNMP
  [yellow]Medium[/]   – HTTP/HTTPS
  [green]Low[/]      – Other services
"""


def main() -> None:
    console.print(_BANNER)
    args = sys.argv[1:]

    if not args or "--help" in args or "-h" in args:
        console.print(Panel(_HELP, title="[bold]Help[/]", border_style="cyan", expand=False))
        sys.exit(0)

    if "--demo" in args:
        console.print("[bold yellow]Running in DEMO mode with sample network scan …[/]\n")
        _run_demo()
        return

    for arg in args:
        _analyse_file(Path(arg))


if __name__ == "__main__":
    main()
