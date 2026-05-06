# Nmap Pro Analyzer - Quick Reference Guide

## 🚀 Quick Start (60 seconds)

```bash
# 1. Install dependencies
pip install python-nmap rich

# 2. Run demo (no nmap required!)
python nmap_pro_analyzer.py --demo

# 3. Scan a target and analyze
sudo nmap -sV -O -p- -oX output.xml 192.168.1.100
python nmap_pro_analyzer.py output.xml
```

---

## 📝 Common Scanning Scenarios

### 🏢 Network Survey (Network Admins)
Identify all servers, their roles, and services on your subnet.

```bash
# Scan entire subnet with service detection
sudo nmap -sV -O -oX network_survey.xml 192.168.1.0/24

# Analyze
python nmap_pro_analyzer.py network_survey.xml
```

**What you'll see:**
- All hosts (up/down)
- Detected OS for each host
- Open ports and services
- Inferred server roles (Web Server, Mail Server, AD, etc.)
- Risk summary

---

### 🔍 Penetration Test (Security Testers)
Deep dive on target systems, identify vulnerabilities.

```bash
# Comprehensive scan of single target
sudo nmap -sV -O -p- --script vuln -oX pentest.xml 10.0.1.50

# Multiple targets
sudo nmap -sV -O -p- -oX pentest_network.xml 10.0.1.0/24

# Analyze
python nmap_pro_analyzer.py pentest.xml
```

**What you'll see:**
- All services with versions (useful for exploit research)
- Critical ports flagged in red
- OS fingerprint for exploit selection
- Infrastructure role (Domain Controller? Database Server?)

---

### 🚨 Critical Service Audit
Quick check for known dangerous ports.

```bash
# Check specific critical ports only
nmap -sV -p 22,80,443,445,389,88,3306,5432,1433,3389 -oX audit.xml 192.168.1.0/24

# Analyze
python nmap_pro_analyzer.py audit.xml
```

**Ports checked:**
- 22 (SSH) – Remote access
- 80/443 (HTTP/HTTPS) – Web services
- 445/139 (SMB) – File sharing
- 389/88 (LDAP/Kerberos) – Active Directory
- 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL) – Databases
- 3389 (RDP) – Remote desktop

---

### ⚡ Fast Service Discovery (Time-Limited)
Quick scan of common ports.

```bash
# Scan only top 100 ports
sudo nmap -sV --top-ports 100 -oX quick_scan.xml 192.168.1.0/24

# Analyze
python nmap_pro_analyzer.py quick_scan.xml
```

**Trade-off:** Faster but may miss less-common services on unusual ports.

---

### 🐧 Linux Server Assessment
Identify and fingerprint Linux systems.

```bash
# OS detection + service versions
sudo nmap -sV -O -p- -oX linux_audit.xml 10.0.0.0/24

# Analyze
python nmap_pro_analyzer.py linux_audit.xml
```

**Look for:**
- SSH versions (often exploitable)
- Database ports open to network
- Container/Kubernetes indicators
- Web services and versions

---

### 🪟 Windows Infrastructure Scan
Focus on Windows-specific services.

```bash
# Kerberos/AD/RDP aware
sudo nmap -sV -O -p 22,88,135,139,389,445,3268,3389,5985,5986 -oX windows_audit.xml 10.0.0.0/24

# Analyze
python nmap_pro_analyzer.py windows_audit.xml
```

**Look for:**
- Domain Controller detection (88/389/445 open)
- RDP availability (3389)
- WinRM (5985/5986) for remote management
- Legacy insecure protocols (NetBIOS/SMB)

---

### 🏪 Data Center / Cloud Infrastructure
Scan infrastructure-scale deployments.

```bash
# Multi-threaded, optimized for speed and scale
sudo nmap -sV -O --max-hostgroup 256 --max-parallelism 100 -oX datacenter.xml 10.0.0.0/16

# Analyze
python nmap_pro_analyzer.py datacenter.xml
```

**Produces:**
- Overall infrastructure map
- Role distribution (how many web servers, databases, etc.)
- OS breakdown (percentage Windows vs Linux)
- Critical service hotspots

---

### 📋 Compliance & Policy Audit
Verify network compliance with security policies.

```bash
# Scan and report on risky ports
sudo nmap -sV -O -p- -oX compliance.xml 192.168.0.0/16

# Analyze (look for "Critical" flags)
python nmap_pro_analyzer.py compliance.xml
```

**Check for:**
- Telnet (port 23) – Should not exist
- Unencrypted services (FTP/SMTP without TLS)
- Exposed databases (3306, 5432, 1433)
- Unnecessary services running

---

## 🎯 Reading the Output

### Green ✅
```
[bold green]UP[/]        → Host is online and responding
 green risk          → Low-risk service
 green open ports    → Found open/accessible services
```

### Red 🔴
```
[bold red]DOWN[/]      → Host is offline/no response
 red risk            → Critical/High risk service
 red down count      → Number of offline hosts
 port 88/445/389     → AD/Kerberos/SMB services
```

### Yellow ⚠️
```
yellow state        → Filtered port (firewall likely)
yellow risk         → Medium-risk service
yellow filtered     → Port might be accessible from inside
```

### Icons 🎨
```
🏢  → Windows Domain Controller / AD
🌍  → Web Server
🐧  → Linux Server
🗄️   → Database Server
✉️   → Mail Server
🔐  → Kerberos / Crypto services
📡  → Network Device
🖥️   → Remote Access (RDP/VNC)
⚡  → Cache/Performance services
```

---

## 🔧 Customizing Scans

### Different Port Ranges

```bash
# Top 1000 ports (default)
nmap -sV -oX scan.xml <target>

# Specific ports
nmap -sV -p 22,80,443,3306 -oX scan.xml <target>

# Port range
nmap -sV -p 1-1000 -oX scan.xml <target>

# All 65535 ports (slow)
nmap -sV -p- -oX scan.xml <target>

# Exclude ports
nmap -sV --exclude-ports 445,139 -oX scan.xml <target>
```

### Scan Speed/Aggressiveness

```bash
# Paranoid (very slow, stealth)
nmap -T0 -sV -oX scan.xml <target>

# Sneaky (slow, less detectable)
nmap -T1 -sV -oX scan.xml <target>

# Polite (default, medium speed)
nmap -T3 -sV -oX scan.xml <target>

# Aggressive (fast)
nmap -T4 -sV -oX scan.xml <target>

# Insane (very fast, may be inaccurate)
nmap -T5 -sV -oX scan.xml <target>
```

### OS Detection Accuracy

```bash
# Basic OS detection
nmap -O -oX scan.xml <target>

# Aggressive OS detection (more accurate)
nmap -O --osscan-guess -oX scan.xml <target>

# With traceroute
nmap -O --traceroute -oX scan.xml <target>
```

---

## 💾 Output Examples

### Single Host: Windows Server

```
Host #1   192.168.1.10
Hostname(s):  dc01.corp.local
Status:      UP
OS Detected:  Windows Server 2019 Standard (Windows)
Ports:       7 found (7 open / 0 closed)

     Port  Protocol  State   Service        Product/Version
    ─────────────────────────────────────────────────────────
       53    tcp    open    domain         Microsoft DNS 10.0
       88    tcp    open    kerberos-sec   Windows Kerberos  [Critical]
      135    tcp    open    msrpc          Windows RPC       [Critical]
      389    tcp    open    ldap           Microsoft LDAP    [Critical]
      445    tcp    open    microsoft-ds   Windows Server    [Critical]
     3268    tcp    open    msft-gc        Active Directory  [Critical]
     3389    tcp    open    ms-wbt-server  Terminal Services [High]

Infrastructure Inference (Windows):
  🏢 Windows Domain Controller
  🔐 Kerberos + SMB Server
  ⚠️  Multiple critical ports open
```

**Reading this:**
- This is a **Domain Controller** (AD)
- **All critical AD ports open** (88, 389, 445)
- **RDP enabled** (3389) – allows remote admin access
- This is a **high-value target** for attackers

---

### Single Host: Linux Web Server

```
Host #2   192.168.1.50
Hostname(s):  web01.corp.local
Status:      UP
OS Detected:  Linux 5.10 - 5.15 (Linux)
Ports:       5 found (5 open / 0 closed)

     Port  Protocol  State   Service     Product/Version
    ──────────────────────────────────────────────────────
       22    tcp    open    ssh         OpenSSH 8.9p1    [High]
       80    tcp    open    http        nginx 1.24.0     [Medium]
      443    tcp    open    https       nginx 1.24.0     [Medium]
     3306    tcp    open    mysql       MySQL 8.0.36     [Critical]
     5432    tcp    open    postgresql  PostgreSQL 14.10 [Critical]

Infrastructure Inference (Linux):
  🌍 Web Server (HTTP+HTTPS)
  🐧 Linux Web Server
  🗄️  MySQL + PostgreSQL (databases exposed to network!)
```

**Reading this:**
- **Web server** serving HTTP/HTTPS
- **Multiple databases accessible from network** – Major risk!
- Databases should ideally only be accessible from app servers (not internet)
- Good: SSH available for administration
- Could benefit from: firewall rules, database network segmentation

---

### Network Summary

```
Source: network.xml
Hosts: 25 total  (23 up / 2 down)  |  Ports: 87 open
OS Breakdown:
  Linux: 15, Windows: 6, Network Device: 2

Host        Status  OS        Ports  Critical  Primary Role
──────────────────────────────────────────────────────────
10.0.1.1    UP      Network    3      0        🌐 DNS / Gateway
10.0.1.10   UP      Windows    7      7 ⚠️     🏢 Domain Controller
10.0.1.50   UP      Linux      5      2        🌍 Web Server
10.0.1.51   UP      Linux      3      1        🗄️  Database
10.0.1.75   UP      Linux      8      2        ✉️  Mail Server
...
```

**Reading this:**
- Most servers are **Linux** (typical for web/app infrastructure)
- **1 Domain Controller** with all 7 critical AD ports open
- **Multiple critical ports** detected across infrastructure
- **Compliance risk** if databases are exposed on network

---

## 📊 Interpreting Risk Levels

### 🔴 Critical Risk
- **What:** Ports 88, 135, 389, 445, 3306, 5432, etc.
- **Why:** Direct exploitation or sensitive data access
- **Action:** Restrict network access, keep patches current
- **Examples:** Domain Controller, exposed database

### 🟠 High Risk
- **What:** Ports 22, 23, 25, 53, 3389, 5900, etc.
- **Why:** Commonly targeted, automation tools available
- **Action:** Monitor closely, strong authentication, whitelisting
- **Examples:** SSH, RDP, SMTP servers

### 🟡 Medium Risk
- **What:** Ports 80, 443, 8080, etc.
- **Why:** Often legitimate but can have vulnerabilities
- **Action:** WAF, regularly patching, secure configuration
- **Examples:** Web servers

### 🟢 Low Risk
- **What:** Other ports and services
- **Why:** Less commonly targeted or lower impact
- **Action:** Maintain baseline security

---

## 🛡️ Security Best Practices

### ✅ Do's

```bash
# ✅ Scan with authorization
sudo nmap -sV -O -oX authorized_scan.xml approved_target

# ✅ Document findings
python nmap_pro_analyzer.py scan.xml > security_audit_$(date +%Y%m%d).txt

# ✅ Use service versions for vulnerability research
# (Shows "SSH 7.4p1" → Look up CVEs for OpenSSH 7.4p1)

# ✅ Restrict database access to internal networks
# If you see 3306/5432 open to world, configure firewall

# ✅ Disable unnecessary services
# If you see Telnet (23), FTP (21) → Disable and use SSH/SFTP

# ✅ Patch identified services
# Always patch versions with known CVEs
```

### ❌ Don'ts

```bash
# ❌ Don't scan without authorization
# Always get written approval before scanning anything

# ❌ Don't ignore critical ports
# If you see 445 open on a non-DC, investigate

# ❌ Don't expose databases to internet
# MySQL/PostgreSQL should never be directly internet-facing

# ❌ Don't keep default credentials
# Services with detected versions often have default creds

# ❌ Don't share raw scan results publicly
# Could reveal security posture to attackers
```

---

## 🆘 Common Questions

**Q: Why don't I see any open ports on my target?**  
A: Either firewall is blocking, or service isn't running. Try different port ranges:
```bash
nmap -sV -p- -T4 -oX scan.xml <target>
```

**Q: How do I know if a service is vulnerable?**  
A: Take the version and search for CVEs:
```
# If you see: "SSH OpenSSH 7.2p2"
# Search: "OpenSSH 7.2p2 exploit" or "OpenSSH 7.2p2 CVE"
```

**Q: What if I see 445 open but it's not a Domain Controller?**  
A: Could be:
- Standalone file server (Samba)
- Windows workstation with file sharing
- NAS device
- Investigate further with `nmap --script smb-os-discovery`

**Q: Why are some ports showing as "filtered" instead of "closed"?**  
A: Firewall is likely dropping packets. The port might be open internally but blocked from your perspective.

**Q: Can I scan multiple networks at once?**  
A: Yes! Nmap supports CIDR notation:
```bash
nmap -sV -O -oX scan.xml 192.168.1.0/24 10.0.0.0/24 172.16.0.0/24
python nmap_pro_analyzer.py scan.xml
```

---

## 📚 Additional Resources

- **Nmap Official:** https://nmap.org
- **Nmap Book:** https://nmap.org/book/
- **CVE Database:** https://cve.mitre.org
- **Exploit Database:** https://www.exploit-db.com
- **OWASP:** https://owasp.org

---

**Last Updated:** 2025  
**Version:** 2.0 (Adaptive, Multi-Scan Support)
