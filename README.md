# 📧 Phishing Investigation Framework

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1566-FF0000?style=for-the-badge)
![Email Forensics](https://img.shields.io/badge/Email-Forensics-orange?style=for-the-badge)


> End-to-end phishing email analysis toolkit — parses raw .eml files, extracts IOCs, detects header anomalies, and generates structured incident reports for SOC analysts.

---

## 📌 Overview

Phishing is the #1 initial access vector in enterprise breaches (MITRE T1566). This framework automates the tedious manual steps of phishing triage — parsing email headers, extracting URLs and attachments, checking SPF/DKIM/DMARC authentication, and producing a complete incident report in seconds.

Built from real-world experience investigating phishing campaigns in a 24x7 SOC environment.

---

## ✨ Features

- **Header Analysis** — SPF, DKIM, DMARC validation and spoofing detection
- **IOC Extraction** — URLs, domains, IPs, and attachment hashes (SHA256)
- **Risk Scoring** — 0–100 risk score with PASS/FAIL per authentication check
- **Attachment Forensics** — SHA256 hash extraction for sandbox submission
- **MITRE Mapping** — Auto-maps findings to T1566.001 and T1566.002
- **JSON Report Output** — Structured reports ready for SIEM ingestion or ticketing

---

## 🛠️ Installation

```bash
git clone https://github.com/shubham8174/Phishing-Investigation-Framework.git
cd Phishing-Investigation-Framework
pip install requests
```

No external API keys required for core functionality.

---

## 🚀 Usage

```bash
# Analyze a .eml file
python phishing_investigator.py suspicious_email.eml
```

**Sample Output:**
```
📧 EMAIL METADATA
   From:    "IT Support" <support@micros0ft-helpdesk.com>
   To:      employee@company.com
   Subject: Urgent: Password Reset Required

🔍 HEADER ANALYSIS
   Risk Score: 80/100
   Verdict:    HIGH RISK
   🔴 SPF check FAILED — email may be spoofed
   ⚠️  Reply-To domain differs from From domain
   🔴 DMARC check FAILED

🔗 EXTRACTED IOCS
   URLs (3):
     - http://malicious-login.xyz/reset?token=abc123
   Attachments:
     - Invoice.exe | SHA256: 44d88612fea8a8f36de82e1278abb02f

🎯 MITRE ATT&CK Mapping
   T1566.001 - Spearphishing Attachment
   T1566.002 - Spearphishing Link

✅ RECOMMENDED ACTIONS
   1. BLOCK sender domain at email gateway
   2. Submit URLs to proxy/web filter blocklist
   3. Alert affected users and reset credentials if clicked
   4. Submit attachments to sandbox for dynamic analysis
   5. Escalate to Tier-2 for full investigation
```

---

## 📊 MITRE ATT&CK Coverage

| Technique | ID | Detection Method |
|---|---|---|
| Spearphishing Attachment | T1566.001 | Attachment extraction + hash analysis |
| Spearphishing Link | T1566.002 | URL extraction + domain reputation |
| Credential Harvesting | T1598.003 | Suspicious login page URL patterns |
| Email Spoofing | T1656 | SPF/DKIM/DMARC header analysis |

---

## 📁 Project Structure

```
Phishing-Investigation-Framework/
│
├── phishing_investigator.py   # Main analysis script
├── samples/                   # Sample .eml files for testing
├── reports/                   # Auto-generated JSON reports
└── README.md
```

---

## 🔮 Roadmap

- [ ] VirusTotal URL reputation checking
- [ ] Automated sandbox submission (Any.run API)
- [ ] Bulk .eml folder processing
- [ ] SIEM alert integration (Sentinel / Splunk webhook)
- [ ] Phishing campaign clustering by IOC similarity

---

## 👤 Author

**Shubham Singh**
MSc Cyber Security — University of Southampton 🇬🇧
Information Security Analyst | Phishing Investigation | SOC Operations

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://www.linkedin.com/in/shubham-singh99/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/shubham8174)


