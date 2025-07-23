import random
import logging
from datetime import datetime, timedelta
from collections import Counter

class SecurityAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.last_threat_detected = None
        self.vulnerabilities = [
            {
                "cve_id": "CVE-2024-1234",
                "severity": "Critical",
                "description": "Remote code execution vulnerability in authentication module",
                "affected_component": "Auth Service",
                "status": "Open",
                "discovery_date": (datetime.now() - timedelta(days=15)).isoformat(),
                "remediation": "Apply security patch #A-257"
            },
            {
                "cve_id": "CVE-2024-5678",
                "severity": "High",
                "description": "SQL injection vulnerability in user input validation",
                "affected_component": "API Gateway",
                "status": "In Progress",
                "discovery_date": (datetime.now() - timedelta(days=7)).isoformat(),
                "remediation": "Implement input sanitization and prepared statements"
            },
            {
                "cve_id": "CVE-2024-9012",
                "severity": "Medium",
                "description": "Cross-site scripting vulnerability in form submission",
                "affected_component": "Web Frontend",
                "status": "Open",
                "discovery_date": (datetime.now() - timedelta(days=3)).isoformat(),
                "remediation": "Implement content security policy and input validation"
            },
            {
                "cve_id": "CVE-2024-3456",
                "severity": "Low",
                "description": "Information disclosure in error messages",
                "affected_component": "Error Handling",
                "status": "Resolved",
                "discovery_date": (datetime.now() - timedelta(days=30)).isoformat(),
                "remediation": "Implement generic error messages in production"
            }
        ]
        
        self.protected_assets = [
            {
                "name": "Web Server",
                "type": "Service",
                "protection_level": "High",
                "last_scan": (datetime.now() - timedelta(hours=6)).isoformat()
            },
            {
                "name": "Database",
                "type": "Data Storage",
                "protection_level": "Critical",
                "last_scan": (datetime.now() - timedelta(hours=12)).isoformat()
            },
            {
                "name": "API Gateway",
                "type": "Service",
                "protection_level": "High",
                "last_scan": (datetime.now() - timedelta(hours=8)).isoformat()
            },
            {
                "name": "Authentication Service",
                "type": "Service",
                "protection_level": "Critical",
                "last_scan": (datetime.now() - timedelta(hours=4)).isoformat()
            },
            {
                "name": "User Data",
                "type": "Data",
                "protection_level": "Critical",
                "last_scan": (datetime.now() - timedelta(hours=12)).isoformat()
            }
        ]
    
    def analyze_threats(self, network_logs):
        """Analyze network logs for potential security threats"""
        # In a real implementation, this would analyze the actual logs
        # For demonstration, we'll generate some sample threats
        threats = []
        
        # Simulate finding 0-3 threats
        num_threats = random.randint(0, 3)
        if num_threats > 0:
            self.last_threat_detected = datetime.now()
            
        for i in range(num_threats):
            threat_type = random.choice([
                "Intrusion Attempt", 
                "Suspicious Traffic", 
                "Port Scan", 
                "DDoS Attempt", 
                "Data Exfiltration",
                "Brute Force Attack",
                "Malware Communication"
            ])
            
            severity = random.choice(["Low", "Medium", "High", "Critical"])
            
            # Generate a random IP address
            source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            # Generate details based on threat type
            if threat_type == "Intrusion Attempt":
                details = "Multiple failed authentication attempts detected"
            elif threat_type == "Suspicious Traffic":
                details = "Unusual outbound traffic pattern detected"
            elif threat_type == "Port Scan":
                details = f"Sequential port scanning from {source_ip}"
            elif threat_type == "DDoS Attempt":
                details = "High volume of incoming connection requests"
            elif threat_type == "Data Exfiltration":
                details = "Large volume of data being sent to external server"
            elif threat_type == "Brute Force Attack":
                details = "Repeated login attempts with different credentials"
            elif threat_type == "Malware Communication":
                details = "Communication with known malicious IP address"
                
            threats.append({
                "id": i + 1,
                "type": threat_type,
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat(),
                "severity": severity,
                "details": details
            })
            
        return threats
    
    def calculate_security_score(self):
        """Calculate overall security score based on threats and vulnerabilities"""
        # In a real implementation, this would use actual metrics
        # For demonstration, generate a score between 0-100
        base_score = 85  # Start with a good baseline
        
        # Deduct points for vulnerabilities
        vulnerability_penalty = 0
        for vuln in self.vulnerabilities:
            if vuln["status"] != "Resolved":
                if vuln["severity"] == "Critical":
                    vulnerability_penalty += 8
                elif vuln["severity"] == "High":
                    vulnerability_penalty += 5
                elif vuln["severity"] == "Medium":
                    vulnerability_penalty += 3
                elif vuln["severity"] == "Low":
                    vulnerability_penalty += 1
                    
        # Recent threats lower the score
        threat_penalty = 0
        if self.last_threat_detected:
            hours_since_threat = (datetime.now() - self.last_threat_detected).total_seconds() / 3600
            if hours_since_threat < 24:
                threat_penalty = 10
            elif hours_since_threat < 72:
                threat_penalty = 5
                
        # Calculate final score, ensuring it stays between 0-100
        score = max(0, min(100, base_score - vulnerability_penalty - threat_penalty))
        return round(score)
    
    def count_vulnerabilities(self):
        """Count the number of unresolved vulnerabilities"""
        return len([v for v in self.vulnerabilities if v["status"] != "Resolved"])
    
    def count_protected_assets(self):
        """Count the number of protected assets"""
        return len(self.protected_assets)
    
    def get_last_threat_time(self):
        """Get the timestamp of the last detected threat"""
        return self.last_threat_detected
    
    def get_vulnerabilities(self):
        """Get the list of vulnerabilities"""
        return self.vulnerabilities
    
    def get_security_overview(self):
        """Get a security overview for the dashboard"""
        security_score = self.calculate_security_score()
        active_threats = random.randint(0, 5)  # Sample data
        
        if self.last_threat_detected:
            last_threat_time = self.last_threat_detected.isoformat()
        else:
            last_threat_time = (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat()
        
        return {
            "security_score": security_score,
            "active_threats": active_threats,
            "vulnerabilities_count": self.count_vulnerabilities(),
            "protected_assets": self.count_protected_assets(),
            "last_threat_time": last_threat_time,
            "security_status": "Good" if security_score >= 80 else "Fair" if security_score >= 60 else "Poor"
        }
    
    def analyze_traffic_security(self, traffic_data):
        """Analyze traffic data for security concerns"""
        if not traffic_data:
            return {
                "status": "error",
                "message": "No traffic data provided for analysis"
            }
        
        try:
            # Count suspicious packets
            suspicious_packets = random.randint(5, 20)
            suspicious_percentage = (suspicious_packets / len(traffic_data)) * 100 if traffic_data else 0
            
            # Count potential threats by category
            threat_categories = [
                "Authentication Failure",
                "Suspicious Outbound",
                "Port Scanning",
                "Unusual Protocol",
                "Data Volume Anomaly"
            ]
            
            threat_counts = {}
            for category in threat_categories:
                threat_counts[category] = random.randint(0, 10)
            
            # Generate recommendation based on findings
            recommendations = []
            for category, count in threat_counts.items():
                if count > 5:
                    if category == "Authentication Failure":
                        recommendations.append("Implement account lockout policies")
                    elif category == "Suspicious Outbound":
                        recommendations.append("Review outbound firewall rules")
                    elif category == "Port Scanning":
                        recommendations.append("Implement port scan detection and blocking")
                    elif category == "Unusual Protocol":
                        recommendations.append("Review allowed protocols and services")
                    elif category == "Data Volume Anomaly":
                        recommendations.append("Implement data loss prevention controls")
            
            if not recommendations:
                recommendations.append("Continue monitoring traffic patterns")
            
            return {
                "suspicious_packets": suspicious_packets,
                "suspicious_percentage": round(suspicious_percentage, 2),
                "threat_categories": [{"category": cat, "count": count} for cat, count in threat_counts.items()],
                "recommendations": recommendations,
                "analysis_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error in traffic security analysis: {e}")
            return {
                "status": "error",
                "message": f"Analysis error: {str(e)}"
            }
    
    def get_security_alerts(self, network_logs, limit=10):
        """Generate security alerts based on network logs"""
        # This is a simplified version that generates demo alerts
        alerts = []
        
        for i in range(random.randint(0, limit)):
            alert_types = [
                "Authentication Failure",
                "Unusual Access Pattern",
                "Port Scanning",
                "Suspicious Outbound Connection",
                "DDoS Attempt",
                "Malware Signature Detected",
                "Data Exfiltration Attempt"
            ]
            
            alert_type = random.choice(alert_types)
            source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            destination_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            severity_map = {
                "Authentication Failure": "Medium",
                "Unusual Access Pattern": "Low",
                "Port Scanning": "Medium",
                "Suspicious Outbound Connection": "High",
                "DDoS Attempt": "Critical",
                "Malware Signature Detected": "Critical",
                "Data Exfiltration Attempt": "High"
            }
            
            severity = severity_map.get(alert_type, "Medium")
            
            # Generate specific details based on alert type
            if alert_type == "Authentication Failure":
                details = f"Multiple failed login attempts from {source_ip}"
            elif alert_type == "Unusual Access Pattern":
                details = f"Abnormal access time or pattern from {source_ip}"
            elif alert_type == "Port Scanning":
                details = f"Sequential port scan detected from {source_ip}"
            elif alert_type == "Suspicious Outbound Connection":
                details = f"Connection to blacklisted IP: {destination_ip}"
            elif alert_type == "DDoS Attempt":
                details = f"High volume of traffic from multiple sources to {destination_ip}"
            elif alert_type == "Malware Signature Detected":
                details = f"Known malware signature detected in traffic from {source_ip}"
            elif alert_type == "Data Exfiltration Attempt":
                details = f"Large data transfer to external IP: {destination_ip}"
            
            alerts.append({
                "id": i + 1,
                "type": alert_type,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "timestamp": (datetime.now() - timedelta(minutes=random.randint(5, 500))).isoformat(),
                "severity": severity,
                "details": details,
                "status": random.choice(["New", "Investigating", "Resolved", "False Positive"])
            })
        
        # Sort by timestamp (newest first)
        alerts.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return alerts[:limit]  # Return only the requested number of alerts