"""
Mock data generator for testing and development.
Generates realistic scan results without requiring actual router access.
"""

import random
from datetime import datetime, timedelta
from typing import Dict, List, Any


class MockDataGenerator:
    """Generate mock scan results for testing"""
    
    # Common router vendors and models
    ROUTER_MODELS = [
        ("Netgear", "Nighthawk R7000", "V1.0.9.88"),
        ("TP-Link", "Archer AX6000", "1.3.1 Build 20210719"),
        ("Asus", "RT-AX88U", "3.0.0.4.388"),
        ("Linksys", "WRT3200ACM", "1.0.10.187766"),
        ("D-Link", "DIR-882", "1.30B06"),
        ("Netgear", "R6700v3", "1.0.4.120"),
        ("TP-Link", "AC1750", "3.20.0 Build 20190919"),
    ]
    
    # Common vulnerabilities with realistic details
    VULNERABILITIES = [
        {
            "title": "Default Admin Credentials",
            "severity": "CRITICAL",
            "description": "Device is using default admin username and password. This allows unauthorized access to the router's configuration interface.",
            "cve_id": None,
            "remediation": "Change default credentials immediately. Use a strong password with at least 12 characters including letters, numbers, and symbols.",
            "cvss_score": 9.8,
        },
        {
            "title": "Outdated Firmware Version",
            "severity": "HIGH",
            "description": "Router firmware is outdated and contains known security vulnerabilities. Current version is missing critical security patches.",
            "cve_id": "CVE-2023-1234",
            "remediation": "Update to the latest firmware version from the manufacturer's website. Enable automatic updates if available.",
            "cvss_score": 7.5,
        },
        {
            "title": "Weak WiFi Encryption (WEP)",
            "severity": "CRITICAL",
            "description": "WiFi network is using outdated WEP encryption which can be cracked in minutes. Network traffic is not adequately protected.",
            "cve_id": None,
            "remediation": "Change WiFi encryption to WPA3 or at minimum WPA2-AES. Disable WEP immediately.",
            "cvss_score": 8.8,
        },
        {
            "title": "UPnP Enabled",
            "severity": "MEDIUM",
            "description": "Universal Plug and Play (UPnP) is enabled, which can be exploited to open ports and bypass firewall rules without authorization.",
            "cve_id": None,
            "remediation": "Disable UPnP in router settings unless specifically required. If needed, use UPnP only with trusted devices.",
            "cvss_score": 6.5,
        },
        {
            "title": "Remote Administration Enabled",
            "severity": "HIGH",
            "description": "Remote administration interface is accessible from the internet, exposing the router to potential attacks.",
            "cve_id": None,
            "remediation": "Disable remote administration unless absolutely necessary. If required, use a VPN and restrict access by IP address.",
            "cvss_score": 7.8,
        },
        {
            "title": "WPS Enabled",
            "severity": "MEDIUM",
            "description": "WiFi Protected Setup (WPS) is enabled and vulnerable to brute force PIN attacks.",
            "cve_id": "CVE-2011-5053",
            "remediation": "Disable WPS in router settings. Use manual WiFi password configuration instead.",
            "cvss_score": 5.9,
        },
        {
            "title": "Open DNS Resolver",
            "severity": "MEDIUM",
            "description": "Router is configured as an open DNS resolver, which can be abused for DNS amplification DDoS attacks.",
            "cve_id": None,
            "remediation": "Configure DNS to only respond to queries from local network. Disable recursive queries from external sources.",
            "cvss_score": 5.3,
        },
        {
            "title": "Telnet Service Enabled",
            "severity": "HIGH",
            "description": "Insecure Telnet service is running. Telnet transmits credentials and data in plaintext.",
            "cve_id": None,
            "remediation": "Disable Telnet service. Use SSH instead if remote command-line access is required.",
            "cvss_score": 7.2,
        },
        {
            "title": "Weak WiFi Password",
            "severity": "HIGH",
            "description": "WiFi password is weak and susceptible to dictionary or brute force attacks.",
            "cve_id": None,
            "remediation": "Change WiFi password to a strong passphrase with at least 16 characters. Avoid common words and patterns.",
            "cvss_score": 7.0,
        },
        {
            "title": "Guest Network Not Isolated",
            "severity": "LOW",
            "description": "Guest WiFi network is not properly isolated from main network, allowing guests to access internal resources.",
            "cve_id": None,
            "remediation": "Enable guest network isolation to prevent access to main network devices and resources.",
            "cvss_score": 4.3,
        },
        {
            "title": "IPv6 Firewall Disabled",
            "severity": "MEDIUM",
            "description": "IPv6 firewall is disabled, potentially exposing devices to direct internet access via IPv6.",
            "cve_id": None,
            "remediation": "Enable IPv6 firewall with rules matching IPv4 firewall policy. Disable IPv6 if not needed.",
            "cvss_score": 5.8,
        },
        {
            "title": "SNMP Community String Default",
            "severity": "MEDIUM",
            "description": "SNMP service is using default community strings (public/private), allowing unauthorized information disclosure.",
            "cve_id": None,
            "remediation": "Change SNMP community strings to complex values or disable SNMP if not needed.",
            "cvss_score": 6.5,
        },
    ]
    
    @staticmethod
    def generate_scan_result(
        target: str = None,
        risk_level: str = None,
        vuln_count: int = None,
        timestamp: datetime = None
    ) -> Dict[str, Any]:
        """
        Generate a mock vulnerability scan result.
        
        Args:
            target: Target IP/hostname (random if None)
            risk_level: Force specific risk level (CRITICAL/HIGH/MEDIUM/LOW)
            vuln_count: Number of vulnerabilities to include (random if None)
            timestamp: Scan timestamp (now if None)
        
        Returns:
            Dictionary containing complete scan results
        """
        if target is None:
            target = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        if timestamp is None:
            timestamp = datetime.now()
        
        # Select random router model
        vendor, model, firmware = random.choice(MockDataGenerator.ROUTER_MODELS)
        device_info = f"{vendor} {model} (Firmware: {firmware})"
        
        # Determine number of vulnerabilities based on risk level
        if vuln_count is None:
            if risk_level == "CRITICAL":
                vuln_count = random.randint(5, 8)
            elif risk_level == "HIGH":
                vuln_count = random.randint(3, 5)
            elif risk_level == "MEDIUM":
                vuln_count = random.randint(1, 3)
            elif risk_level == "LOW":
                vuln_count = random.randint(0, 1)
            else:
                vuln_count = random.randint(0, 6)
        
        # Select random vulnerabilities
        selected_vulns = random.sample(
            MockDataGenerator.VULNERABILITIES,
            min(vuln_count, len(MockDataGenerator.VULNERABILITIES))
        )
        
        vulnerabilities = []
        for vuln in selected_vulns:
            vulnerabilities.append({
                "title": vuln["title"],
                "severity": vuln["severity"],
                "description": vuln["description"],
                "cve_id": vuln["cve_id"],
                "remediation": vuln["remediation"],
                "cvss_score": vuln["cvss_score"],
                "detected_at": timestamp.isoformat(),
            })
        
        # Calculate risk score
        if vulnerabilities:
            severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}
            total_weight = sum(severity_weights.get(v["severity"], 0) for v in vulnerabilities)
            risk_score = min(10.0, total_weight / len(vulnerabilities))
        else:
            risk_score = 0.0
        
        # Determine risk level
        if risk_score >= 8.0:
            calculated_risk_level = "CRITICAL"
        elif risk_score >= 6.0:
            calculated_risk_level = "HIGH"
        elif risk_score >= 3.0:
            calculated_risk_level = "MEDIUM"
        else:
            calculated_risk_level = "LOW"
        
        # Generate recommendations
        recommendations = []
        has_critical = any(v["severity"] == "CRITICAL" for v in vulnerabilities)
        has_high = any(v["severity"] == "HIGH" for v in vulnerabilities)
        
        if has_critical:
            recommendations.append({
                "priority": "URGENT",
                "recommendation": "Address critical vulnerabilities immediately - these pose severe security risks",
            })
        
        if has_high:
            recommendations.append({
                "priority": "HIGH",
                "recommendation": "Update firmware and review security settings within 24 hours",
            })
        
        if vuln_count > 3:
            recommendations.append({
                "priority": "MEDIUM",
                "recommendation": "Conduct a comprehensive security audit of all router settings",
            })
        
        recommendations.append({
            "priority": "LOW",
            "recommendation": "Enable automatic security updates and monitoring",
        })
        
        recommendations.append({
            "priority": "LOW",
            "recommendation": "Review and document all port forwarding and firewall rules",
        })
        
        # Build complete result
        return {
            "target": target,
            "scan_timestamp": timestamp.isoformat(),
            "device_info": device_info,
            "vendor": vendor,
            "model": model,
            "firmware_version": firmware,
            "risk_score": round(risk_score, 1),
            "risk_level": calculated_risk_level,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "recommendations": recommendations,
            "scan_duration": round(random.uniform(5.2, 45.8), 1),
        }
    
    @staticmethod
    def generate_historical_scans(
        target: str,
        count: int = 10,
        days_back: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Generate a series of historical scans showing security trends.
        
        Args:
            target: Target IP/hostname
            count: Number of historical scans to generate
            days_back: How many days back to generate scans
        
        Returns:
            List of scan results ordered chronologically
        """
        scans = []
        now = datetime.now()
        
        # Start with worse security and gradually improve
        initial_vuln_count = random.randint(5, 8)
        
        for i in range(count):
            # Distribute scans over time period
            days_offset = (days_back / count) * i
            scan_time = now - timedelta(days=days_offset)
            
            # Gradually reduce vulnerabilities over time (showing improvement)
            # Add some randomness
            improvement_factor = i / count
            vuln_count = max(0, int(initial_vuln_count * (1 - improvement_factor * 0.7)))
            vuln_count += random.randint(-1, 1)  # Add variance
            vuln_count = max(0, vuln_count)
            
            scan = MockDataGenerator.generate_scan_result(
                target=target,
                vuln_count=vuln_count,
                timestamp=scan_time
            )
            scans.append(scan)
        
        # Return in chronological order (oldest first)
        return sorted(scans, key=lambda x: x["scan_timestamp"])
    
    @staticmethod
    def generate_diverse_scans(count: int = 5) -> List[Dict[str, Any]]:
        """
        Generate diverse scans of different devices with varying security postures.
        
        Args:
            count: Number of different device scans to generate
        
        Returns:
            List of scan results for different targets
        """
        scans = []
        risk_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        
        for i in range(count):
            target = f"192.168.1.{i + 1}"
            risk_level = risk_levels[i % len(risk_levels)] if i < len(risk_levels) else None
            
            scan = MockDataGenerator.generate_scan_result(
                target=target,
                risk_level=risk_level
            )
            scans.append(scan)
        
        return scans


# Convenience functions for quick testing
def get_sample_scan() -> Dict[str, Any]:
    """Get a single sample scan result"""
    return MockDataGenerator.generate_scan_result()


def get_critical_scan() -> Dict[str, Any]:
    """Get a scan with critical vulnerabilities"""
    return MockDataGenerator.generate_scan_result(risk_level="CRITICAL")


def get_clean_scan() -> Dict[str, Any]:
    """Get a scan with no vulnerabilities"""
    return MockDataGenerator.generate_scan_result(vuln_count=0)


def get_history(target: str = "192.168.1.1", count: int = 10) -> List[Dict[str, Any]]:
    """Get historical scans for a target"""
    return MockDataGenerator.generate_historical_scans(target, count)


if __name__ == "__main__":
    # Demo usage
    print("=== Sample Scan Result ===")
    sample = get_sample_scan()
    print(f"Target: {sample['target']}")
    print(f"Device: {sample['device_info']}")
    print(f"Risk Score: {sample['risk_score']}/10.0 ({sample['risk_level']})")
    print(f"Vulnerabilities: {sample['vulnerability_count']}")
    
    print("\n=== Critical Security Issues ===")
    critical = get_critical_scan()
    print(f"Risk Score: {critical['risk_score']}/10.0")
    print(f"Vulnerabilities Found: {critical['vulnerability_count']}")
    for vuln in critical['vulnerabilities'][:3]:
        print(f"  - {vuln['title']} ({vuln['severity']})")
    
    print("\n=== Historical Trend ===")
    history = get_history(count=5)
    for scan in history:
        print(f"{scan['scan_timestamp'][:10]}: {scan['vulnerability_count']} vulnerabilities (Risk: {scan['risk_score']})")
