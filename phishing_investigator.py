"""
Phishing Investigation Framework
==================================
Author: Shubham Singh | github.com/shubhamsingh99
MITRE ATT&CK: T1566 - Phishing

Parses raw email files (.eml), extracts IOCs, checks reputation,
and generates structured incident reports for SOC analysts.
"""

import email
import re
import hashlib
import json
import urllib.parse
from email import policy
from email.parser import BytesParser
from datetime import datetime


# ─── IOC EXTRACTION ──────────────────────────────────────────────────────────

def extract_iocs_from_email(eml_path: str) -> dict:
    """Extract all IOCs from a raw .eml file."""
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                if payload:
                    file_hash = hashlib.sha256(payload).hexdigest()
                    attachments.append({"filename": filename, "sha256": file_hash, "size_bytes": len(payload)})
            elif content_type in ["text/plain", "text/html"]:
                try:
                    body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                except Exception:
                    pass
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")

    # Extract URLs
    urls = list(set(re.findall(r'https?://[^\s<>"\']+', body)))

    # Extract IPs
    ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)))

    # Extract domains from URLs
    domains = []
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc:
                domains.append(parsed.netloc.lower())
        except Exception:
            pass

    return {
        "metadata": {
            "from": str(msg.get("From", "")),
            "to": str(msg.get("To", "")),
            "subject": str(msg.get("Subject", "")),
            "date": str(msg.get("Date", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "reply_to": str(msg.get("Reply-To", "")),
            "return_path": str(msg.get("Return-Path", "")),
        },
        "iocs": {
            "urls": urls[:20],
            "domains": list(set(domains))[:20],
            "ips": ips[:10],
            "attachments": attachments
        }
    }


# ─── HEADER ANALYSIS ─────────────────────────────────────────────────────────

def analyze_headers(eml_path: str) -> dict:
    """Analyze email headers for spoofing and anomalies."""
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    findings = []
    risk_score = 0

    sender = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))

    # Check Reply-To mismatch (common phishing indicator)
    if reply_to and reply_to not in sender:
        findings.append("⚠️ Reply-To domain differs from From domain (possible spoofing)")
        risk_score += 30

    # Check Return-Path mismatch
    if return_path and return_path not in sender:
        findings.append("⚠️ Return-Path differs from From address")
        risk_score += 20

    # Check for SPF/DKIM/DMARC in Received headers
    received_spf = str(msg.get("Received-SPF", ""))
    auth_results = str(msg.get("Authentication-Results", ""))

    if "fail" in received_spf.lower():
        findings.append("🔴 SPF check FAILED — email may be spoofed")
        risk_score += 40
    elif "pass" in received_spf.lower():
        findings.append("✅ SPF check passed")

    if "dkim=fail" in auth_results.lower():
        findings.append("🔴 DKIM signature FAILED")
        risk_score += 30
    elif "dkim=pass" in auth_results.lower():
        findings.append("✅ DKIM check passed")

    if "dmarc=fail" in auth_results.lower():
        findings.append("🔴 DMARC check FAILED")
        risk_score += 30

    verdict = "HIGH RISK" if risk_score >= 60 else "MEDIUM RISK" if risk_score >= 30 else "LOW RISK"

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "findings": findings
    }


# ─── REPORT GENERATOR ────────────────────────────────────────────────────────

def generate_phishing_report(eml_path: str) -> None:
    """Full phishing investigation pipeline."""
    print(f"\n[*] Analyzing: {eml_path}")
    print("=" * 60)

    ioc_data = extract_iocs_from_email(eml_path)
    header_analysis = analyze_headers(eml_path)

    meta = ioc_data["metadata"]
    iocs = ioc_data["iocs"]

    print(f"\n📧 EMAIL METADATA")
    print(f"   From:    {meta['from']}")
    print(f"   To:      {meta['to']}")
    print(f"   Subject: {meta['subject']}")
    print(f"   Date:    {meta['date']}")

    print(f"\n🔍 HEADER ANALYSIS")
    print(f"   Risk Score: {header_analysis['risk_score']}/100")
    print(f"   Verdict:    {header_analysis['verdict']}")
    for finding in header_analysis["findings"]:
        print(f"   {finding}")

    print(f"\n🔗 EXTRACTED IOCS")
    print(f"   URLs ({len(iocs['urls'])}):")
    for url in iocs["urls"][:5]:
        print(f"     - {url}")

    print(f"   Domains ({len(iocs['domains'])}):")
    for domain in iocs["domains"][:5]:
        print(f"     - {domain}")

    print(f"   IPs ({len(iocs['ips'])}):")
    for ip in iocs["ips"]:
        print(f"     - {ip}")

    if iocs["attachments"]:
        print(f"   Attachments:")
        for att in iocs["attachments"]:
            print(f"     - {att['filename']} | SHA256: {att['sha256']}")

    print(f"\n🎯 MITRE ATT&CK Mapping")
    print(f"   T1566.001 - Spearphishing Attachment" if iocs["attachments"] else "")
    print(f"   T1566.002 - Spearphishing Link" if iocs["urls"] else "")
    print(f"   T1598.003 - Spearphishing Link (Credential Harvest)")

    print(f"\n✅ RECOMMENDED ACTIONS")
    if header_analysis["risk_score"] >= 60:
        print("   1. BLOCK sender domain at email gateway")
        print("   2. Submit URLs to proxy/web filter blocklist")
        print("   3. Alert affected users and reset credentials if clicked")
        print("   4. Submit attachments to sandbox for dynamic analysis")
        print("   5. Escalate to Tier-2 for full investigation")
    else:
        print("   1. Monitor for similar patterns")
        print("   2. Educate user on phishing awareness")

    # Save JSON report
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "analyst": "Shubham Singh",
        "metadata": meta,
        "header_analysis": header_analysis,
        "iocs": iocs,
        "mitre_techniques": ["T1566.001", "T1566.002"]
    }
    filename = f"phishing_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Full report saved: {filename}")


# ─── MAIN ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        generate_phishing_report(sys.argv[1])
    else:
        print("Usage: python phishing_investigator.py <email.eml>")
        print("Example: python phishing_investigator.py suspicious_email.eml")
