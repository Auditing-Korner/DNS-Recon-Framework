# DNS Advanced Recon by RFS

**DNS Advanced Recon by RFS** is a specialized toolkit designed for advanced reconnaissance and enumeration of Domain Name System (DNS) infrastructures. Built for Red Team operations and cybersecurity researchers, this tool facilitates deep inspection of DNS records, subdomain enumeration, attack surface mapping, and anomaly detection in DNS configurations.

## 🚀 Features

- 🔍 **Recursive Subdomain Enumeration** (via brute-force, wordlists, and passive sources)
- 🌐 **Zone Transfer Checks** and misconfiguration analysis
- 📡 **Wildcard DNS Detection** and evasion techniques
- 🕵️ **Advanced PTR and Reverse DNS Lookups**
- 🔗 **DNSSEC Validation and Analysis**
- 🧠 **Customizable DNS Query Engine** (A, AAAA, MX, NS, TXT, CNAME, SOA, etc.)
- 🗺️ **DNS Topology Mapping** (visualizing infrastructure relationships)
- 🎯 **Active and Passive Recon Modes**
- 📓 **Exportable Reports** in JSON, CSV, and markdown
- 🛡️ **Red and Blue Team Use Cases**

## 🔧 Installation

```bash
git clone https://github.com/<your-username>/dns-advanced-recon-rfs.git
cd dns-advanced-recon-rfs
pip install -r requirements.txt
