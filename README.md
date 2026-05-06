# Nmap Pro Analyzer
### Professional, Adaptive Nmap XML Parser with Infrastructure Intelligence

A powerful Python tool that intelligently parses **any** Nmap XML scan output and displays results in a beautiful, color-coded terminal interface with automatic infrastructure role detection and risk stratification.

---

## 🚀 Features

✅ **Universal Compatibility** – Works with ANY nmap scan type (network sweeps, single hosts, service-focused scans)  
✅ **Automatic OS Detection** – Identifies Windows, Linux, macOS, networking equipment, NAS devices, containers, etc.  
✅ **Smart Role Inference** – Auto-detects server purpose (Web Server, Mail Server, Database, Docker Host, DC, etc.)  
✅ **Risk Stratification** – Port-based risk scoring (Critical/High/Medium/Low)  
✅ **Beautiful Terminal Output** – Rich color-coded tables with icons and formatting  
✅ **Comprehensive Analysis** – Shows services, versions, hostnames, OS, inferred roles  
✅ **Summary Statistics** – Aggregate scan data, OS breakdown, critical port count  
✅ **Zero Dependencies on nmap Binary** – Only needs the XML output file  
✅ **Graceful Error Handling** – Works with incomplete/partial scans  

---

## 📦 Installation
## 🚀 Installation & Setup

To install the tool and make it accessible from anywhere in your terminal, run the following commands:

```bash
git clone https://github.com/NourdineElmassaoudi/Nmap-Pro-Analyzer.git
cd Nmap-Pro-Analyzer
chmod +x install.sh
./install.sh
### 1. Install Python Dependencies

```bash
pip install python-nmap rich
```

**One-line install:**
```bash
pip install python-nmap rich --break-system-packages
```

### 2. Make Script Executable (Optional)

```bash
chmod +x nmap_pro_analyzer.py
```

---

## 📖 Usage

### Basic Usage

```bash
# Single scan
python nmap_pro_analyzer.py scan.xml

# Multiple scans
python nmap_pro_analyzer.py scan1.xml scan2.xml scan3.xml

# Demo mode (no nmap binary needed!)
python nmap_pro_analyzer.py --demo

# Help
python nmap_pro_analyzer.py --help
```

### Generate Nmap XML Output

The script requires Nmap output in **XML format** (created with `-oX` flag).

#### Full Service & OS Detection Scan
```bash
sudo nmap -sV -O -p- -oX full_scan.xml <target>
```
- `-sV` → Probe ports to determine service/version
- `-O` → Enable OS detection
- `-p-` → Scan all 65535 ports
- `-oX` → Output as XML

#### Network Sweep (Multiple Hosts)
```bash
sudo nmap -sV -O -oX network.xml 192.168.1.0/24
```
Scans entire network segment.

#### Aggressive Service Detection
```bash
sudo nmap -sV --script nmap-service-probes -p- -oX services.xml <target>
```
Deep service enumeration with Nmap scripts.

#### Quick Service Scan (Common Ports)
```bash
sudo nmap -sV -p 22,80,443,3306,5432,445,389,88 -oX quick_scan.xml <target>
```
Faster scan of commonly exploited services.

#### OS + Service Detection (Balanced)
```bash
sudo nmap -sV -O -p- --top-ports 1000 -oX balanced.xml <target>
```

---

## 🔍 Understanding the Output

### Host Block Layout

```
╭──────────────────────────────────────╮
│ Host #1   192.168.1.10              │
│ Hostname(s):  dc01.corp.local       │
│ Status:      UP                     │
│ OS Detected:  Windows Server 2019   │
│ Ports:  7 found (7 open / 0 closed) │
╰──────────────────────────────────────╯

     Port  Protocol  State   Service    Product/Version      Risk
────────────────────────────────────────────────────────────────
       53    tcp    open    domain     Microsoft DNS 10.0   High
       88    tcp    open    kerberos   Microsoft Kerberos   Critical
      389    tcp    open    ldap       Microsoft LDAP 10.0  Critical
      445    tcp    open    microsoft  Windows Server 2019  Critical

╭─ Infrastructure Inference (Windows) ──╮
│  🏢 Windows Domain Controller         │
│  🏢 Active Directory Server           │
│  🔐 Kerberos + SMB Server            │
╰──────────────────────────────────────╯
```

### Color Legend

| Color | Meaning | Examples |
|-------|---------|----------|
| 🟢 **Green** | Service Up / Open | Active ports |
| 🔴 **Red** | Critical Risk / Down | AD/Database/SMB ports |
| 🟡 **Yellow** | Medium Risk / Filtered | HTTP/HTTPS |
| 🟢 **Green** | Low Risk | Standard services |
| 🟣 **Magenta** | OS/Role Info | Infrastructure type |
| 🔵 **Cyan** | Headers/Details | Host info, service names |

### Risk Levels

| Level | Risk | Examples |
|-------|------|----------|
| **Critical** 🔴 | Immediate Attention | AD (88,389,445), Exposed DB (3306,5432,1433), RDP (3389), RCE services |
| **High** 🟠 | Worth Investigation | SSH (22), FTP (21), SMTP (25), DNS (53), SNMP (161), RDP (3389) |
| **Medium** 🟡 | Standard Services | HTTP (80), HTTPS (443) |
| **Low** 🟢 | General Services | Unknown/less critical ports |

---

## 🎯 Recognized Infrastructure Roles

The analyzer automatically detects:

### Windows/Active Directory
- 🏢 Windows Domain Controller
- 🏢 Active Directory Server
- 🔐 Kerberos + SMB Server
- 🖥️ Windows RDP Server
- ⚙️ WinRM Management Host

### Linux/Unix
- 🐧 Linux Web Server
- 🐧 Linux Application Server
- 🖥️ SSH Server (Linux/Unix)

### Web Services
- 🌍 Web Server (HTTP+HTTPS)
- 🔒 HTTPS Server
- ⚡ API/App Server
- 🔄 Reverse Proxy / Load Balancer

### Databases
- 🗄️ MySQL/MariaDB Database
- 🗄️ PostgreSQL Database
- 🗄️ MSSQL Server Database
- 🗄️ Oracle Database
- 🗄️ MongoDB Database
- ⚡ Redis/Memcached

### Email & Communication
- ✉️ Mail Server (full stack)
- ✉️ Mail Server (SMTP+IMAP)
- 🌐 DNS Server

### Storage & File Sharing
- 📁 NFS Server
- 📁 SMB/Samba File Server
- 📦 FTP Server
- 📦 SFTP/SSH File Access

### Network & Infrastructure
- 📡 SNMP Network Device
- 🔌 Network Infrastructure
- 🔌 Network Device (Router/Switch/Firewall)

### Containers & Orchestration
- 🐳 Docker Host
- ☸️ Kubernetes Node
- 📦 Container Registry

### Legacy/Dangerous Services
- ⚠️ Telnet (legacy/insecure)
- ⚠️ Rsh/Rlogin (dangerous)

---

## 📊 Summary Statistics

At the end of each scan, you'll see:

```
Source: scan.xml
Hosts: 10 total  (8 up / 2 down)  |  Ports: 45 open
OS Breakdown:
  Linux: 5, Windows: 2, Network Device: 1
```

This shows:
- Total hosts scanned
- Up vs Down hosts
- Total open ports across all hosts
- Distribution of detected OSes

---

## 💡 Real-World Examples

### Example 1: Penetration Test Results
```bash
# Run a comprehensive scan
sudo nmap -sV -O -p- -oX pentest.xml 192.168.1.100

# Analyze results
python nmap_pro_analyzer.py pentest.xml
```
Shows immediate critical risks, open databases, RDP servers, AD services.

### Example 2: Network Survey
```bash
# Scan entire subnet
sudo nmap -sV -O -oX subnet.xml 192.168.10.0/24

# Analyze
python nmap_pro_analyzer.py subnet.xml
```
Shows all hosts, their roles, OS types, and critical services in network.

### Example 3: Multi-Location Analysis
```bash
# Scan multiple networks
sudo nmap -sV -O -oX office.xml 192.168.1.0/24
sudo nmap -sV -O -oX datacenter.xml 10.0.0.0/24
sudo nmap -sV -O -oX branch.xml 172.16.0.0/24

# Analyze all
python nmap_pro_analyzer.py office.xml datacenter.xml branch.xml
```
See infrastructure across all locations, identify risky patterns.

### Example 4: Quick Port Check
```bash
# Fast service scan
nmap -sV -p 22,80,443,3306,5432,445,389,88,135 -oX services.xml 10.0.1.0/24

# Quick analysis
python nmap_pro_analyzer.py services.xml
```

---

## 🔬 Technical Details

### Port Risk Classification

The script uses a predefined `RISK_MAP` dictionary that classifies ports:

```python
# Critical Ports (AD/Kerberos/SMB/Database)
88, 135, 137, 138, 139, 389, 445, 464, 636, 3268, 3269  # AD
1433, 1521, 3306, 5432, 6379, 27017                     # Databases
23, 512, 513, 514, 5900, 5985, 5986                     # Remote access

# High Risk Ports (SSH, FTP, SMTP, SNMP, RDP)
21, 22, 25, 53, 110, 143, 161, 2049, 3389, 8080, 8443

# Medium Risk (HTTP/HTTPS)
80, 443, 8000, 8888

# Low Risk (everything else)
```

### Role Inference Algorithm

1. Extract all **open ports** from each host
2. Match against role signatures (require certain port combinations)
3. Score matches by "confidence" (required + optional ports present)
4. Return top 3 matches sorted by confidence
5. Use OS hint to filter (e.g., "Windows" → Show Windows-specific roles)

### OS Detection

Extracts OS from Nmap's `<osmatch>` element:
- Classifies into families: Windows, Linux, macOS, BSD, Network Device, Printer, NAS
- Shows in host header and affects role inference

---

## 🛠️ Troubleshooting

### "File not found" Error
```
[ERROR] File not found: scan.xml
```
**Solution:** Make sure the XML file path is correct and readable.

### "Malformed XML" Error
```
[ERROR] Malformed XML in 'scan.xml'
```
**Solution:** Verify you used `-oX` flag with nmap:
```bash
nmap -sV -oX output.xml <target>
```

### "python-nmap is not installed"
```
[ERROR] python-nmap is not installed.
  Run:  pip install python-nmap
```
**Solution:**
```bash
pip install python-nmap rich --break-system-packages
```

### No ports detected on known-open host
This can happen if Nmap didn't probe those ports. Re-scan with:
```bash
nmap -sV -p- -oX full.xml <target>
```

---

## 📝 Advanced Usage

### Piping Output
```bash
# Save colored output to file
python nmap_pro_analyzer.py scan.xml > results.txt

# Or use `-` to write plain text
python nmap_pro_analyzer.py scan.xml --plain
```

### Combining Multiple Scans
```bash
# Scan different aspects, then analyze together
sudo nmap -sV -p- -oX tcp_scan.xml <target>
python nmap_pro_analyzer.py tcp_scan.xml
```

### Scripting Integration
```python
# Use in your own Python scripts
from nmap_pro_analyzer import parse_xml, infer_roles
from pathlib import Path

results = parse_xml(Path("scan.xml"))
for host in results:
    if host.status.lower() == "up":
        roles = infer_roles(host.open_port_numbers, host.os_match)
        print(f"{host.ip}: {roles}")
```

---

## 🔐 Security Notes

- This tool is **read-only** – it only parses and displays data
- Ensure you have **authorization** before running nmap scans
- Keep discovered credentials/services **confidential**
- Use in compliance with **security policy** and **applicable laws**

---

## 📄 License

This script is provided as-is for educational and authorized security assessment purposes.

---

## 🆘 Support & Bugs

- **Check the help menu:** `python nmap_pro_analyzer.py --help`
- **Test with demo:** `python nmap_pro_analyzer.py --demo`
- **Verify nmap output:** Make sure XML is valid with `xmllint scan.xml`

---

## 🎓 Learn More

- **Nmap Manual:** https://nmap.org/book/man.html
- **Python-Nmap Docs:** https://xael.org/pages/python-nmap-en.html
- **Rich Library Docs:** https://rich.readthedocs.io/

---

**Made for infrastructure security assessment and penetration testing.**
