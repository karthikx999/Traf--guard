import random
from datetime import datetime, timedelta
import logging
import numpy as np
from collections import defaultdict, Counter

class MLAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.models_initialized = False
        self.initialize_models()

    def initialize_models(self):
        """Initialize ML models for network analysis"""
        # In a real implementation, this would load trained models
        self.logger.info("Initializing ML models for network traffic analysis")
        self.models_initialized = True

    def analyze_traffic(self, network_data):
        """Analyze network traffic for patterns and anomalies"""
        if not self.models_initialized:
            self.initialize_models()
        
        # This would use the actual network data in a real implementation
        # For now, we'll return sample analysis results
        return {
            "traffic_classification": {
                "normal": 85.5,
                "suspicious": 12.2,
                "malicious": 2.3
            },
            "anomaly_score": random.uniform(0.1, 0.9),
            "detected_patterns": [
                {
                    "pattern_type": "periodic_communication",
                    "confidence": random.uniform(0.7, 0.99),
                    "details": "Regular outbound connection every 30 minutes"
                },
                {
                    "pattern_type": "data_exfiltration",
                    "confidence": random.uniform(0.1, 0.8),
                    "details": "Unusual data volume in outbound traffic"
                }
            ]
        }

    def predict_traffic_load(self, time_period="hour"):
        """Predict network traffic load for the upcoming time period"""
        current_time = datetime.now()
        timestamps = []
        values = []
        
        if time_period == "hour":
            # Generate hourly predictions
            for i in range(12):
                timestamps.append((current_time + timedelta(minutes=i*5)).strftime("%H:%M"))
                # Create a somewhat realistic traffic pattern
                hour_factor = current_time.hour
                if 9 <= hour_factor <= 17:  # Business hours
                    base_value = random.uniform(70, 90)
                else:
                    base_value = random.uniform(30, 60)
                values.append(base_value + random.uniform(-10, 10))
        elif time_period == "day":
            # Generate daily predictions
            for i in range(24):
                timestamps.append((current_time + timedelta(hours=i)).strftime("%H:00"))
                hour = (current_time.hour + i) % 24
                if 9 <= hour <= 17:  # Business hours
                    base_value = random.uniform(70, 90)
                else:
                    base_value = random.uniform(30, 60)
                values.append(base_value + random.uniform(-10, 10))
        elif time_period == "week":
            # Generate weekly predictions
            for i in range(7):
                day = (current_time + timedelta(days=i)).strftime("%a")
                timestamps.append(day)
                if day in ["Sat", "Sun"]:  # Weekend
                    base_value = random.uniform(30, 50)
                else:  # Weekday
                    base_value = random.uniform(60, 100)
                values.append(base_value + random.uniform(-10, 15))
        
        return {
            "timestamps": timestamps,
            "values": values,
            "unit": "Mbps",
            "prediction_period": time_period
        }

    def analyze_status_codes(self):
        """Analyze HTTP status codes from collected network traffic"""
        # In a real implementation, this would analyze actual data
        # For now, return sample data
        return [
            {"status_code": "200", "count": random.randint(8000, 12000)},
            {"status_code": "301", "count": random.randint(100, 600)},
            {"status_code": "404", "count": random.randint(50, 350)},
            {"status_code": "500", "count": random.randint(10, 110)},
            {"status_code": "403", "count": random.randint(20, 100)},
            {"status_code": "304", "count": random.randint(500, 2000)}
        ]

    def detect_anomalies(self, data):
        """Detect anomalies in network traffic patterns"""
        # In a real implementation, this would use ML to find anomalies
        # For demo purposes, we'll generate some sample anomalies
        
        anomaly_count = random.randint(0, 3)  # 0-3 anomalies
        anomaly_details = []
        
        if anomaly_count > 0:
            anomaly_types = [
                "Unusual Port Access",
                "Traffic Spike",
                "Protocol Deviation",
                "Connection Pattern",
                "Data Volume Anomaly"
            ]
            
            # Generate random anomaly details
            for _ in range(anomaly_count):
                anomaly_type = random.choice(anomaly_types)
                confidence = round(random.uniform(0.6, 0.95), 2)
                
                anomaly_detail = {
                    "type": anomaly_type,
                    "confidence": confidence,
                    "timestamp": (datetime.now() - timedelta(minutes=random.randint(5, 120))).isoformat()
                }
                
                # Add type-specific details
                if anomaly_type == "Unusual Port Access":
                    anomaly_detail["source_ip"] = f"192.168.1.{random.randint(1, 254)}"
                    anomaly_detail["port"] = random.randint(1024, 65535)
                    anomaly_detail["severity"] = "Medium"
                    anomaly_detail["affected_metric"] = "Port Activity"
                    anomaly_detail["details"] = f"Unusual access to port {anomaly_detail['port']} from {anomaly_detail['source_ip']}"
                
                elif anomaly_type == "Traffic Spike":
                    anomaly_detail["affected_service"] = random.choice(["Web Server", "Database", "API Gateway", "Authentication"])
                    anomaly_detail["magnitude"] = f"{random.randint(200, 500)}%"
                    anomaly_detail["severity"] = "High"
                    anomaly_detail["affected_metric"] = "Traffic Volume"
                    anomaly_detail["details"] = f"Sudden {anomaly_detail['magnitude']} increase in traffic to {anomaly_detail['affected_service']}"
                
                elif anomaly_type == "Protocol Deviation":
                    anomaly_detail["protocol"] = random.choice(["HTTP", "HTTPS", "SSH", "FTP", "SMTP"])
                    anomaly_detail["severity"] = "Low"
                    anomaly_detail["affected_metric"] = "Protocol Behavior"
                    anomaly_detail["details"] = f"Unusual {anomaly_detail['protocol']} traffic pattern detected"
                
                elif anomaly_type == "Connection Pattern":
                    anomaly_detail["pattern"] = random.choice(["Periodic", "Burst", "Sustained", "Scanning"])
                    anomaly_detail["source_ip"] = f"10.0.0.{random.randint(1, 254)}"
                    anomaly_detail["severity"] = "Medium"
                    anomaly_detail["affected_metric"] = "Connection Patterns"
                    anomaly_detail["details"] = f"{anomaly_detail['pattern']} connection pattern from {anomaly_detail['source_ip']}"
                
                elif anomaly_type == "Data Volume Anomaly":
                    anomaly_detail["direction"] = random.choice(["Inbound", "Outbound"])
                    anomaly_detail["volume"] = f"{random.randint(50, 500)}MB"
                    anomaly_detail["severity"] = "High" if anomaly_detail["direction"] == "Outbound" else "Medium"
                    anomaly_detail["affected_metric"] = "Data Volume"
                    anomaly_detail["details"] = f"Unusual {anomaly_detail['direction']} data volume: {anomaly_detail['volume']}"
                
                anomaly_details.append(anomaly_detail)
        
        return {
            "anomalies_detected": len(anomaly_details),
            "anomaly_details": anomaly_details
        }

    def analyze_network_data(self, data):
        """Comprehensive analysis of network data"""
        if not data:
            return {
                "status": "error",
                "message": "No data provided for analysis"
            }
        
        try:
            # In a real implementation, this would analyze the provided data
            # For demo purposes, we'll create a sample analysis
            
            # Count protocols
            protocol_count = defaultdict(int)
            for item in data:
                protocol = item.get('protocol')
                if protocol:
                    protocol_count[protocol] += 1
            
            # Protocol distribution
            total_packets = len(data)
            protocol_distribution = []
            for protocol, count in protocol_count.items():
                protocol_name = self._get_protocol_name(protocol)
                percentage = (count / total_packets) * 100 if total_packets > 0 else 0
                protocol_distribution.append({
                    "protocol": protocol_name,
                    "count": count,
                    "percentage": round(percentage, 2)
                })
            
            # Traffic patterns
            traffic_patterns = self._analyze_traffic_patterns(data)
            
            # Connection analysis
            connection_analysis = self._analyze_connections(data)
            
            return {
                "total_packets_analyzed": total_packets,
                "protocol_distribution": protocol_distribution,
                "traffic_patterns": traffic_patterns,
                "connection_analysis": connection_analysis,
                "analysis_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error in network data analysis: {e}")
            return {
                "status": "error",
                "message": f"Analysis error: {str(e)}"
            }
    
    def _get_protocol_name(self, protocol_number):
        """Convert protocol number to name"""
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            47: "GRE",
            50: "ESP",
            51: "AH",
            58: "ICMPv6",
            89: "OSPF",
            132: "SCTP"
        }
        
        if isinstance(protocol_number, str):
            try:
                protocol_number = int(protocol_number)
            except (ValueError, TypeError):
                return protocol_number
                
        return protocol_map.get(protocol_number, f"Unknown ({protocol_number})")
    
    def _analyze_traffic_patterns(self, data):
        """Analyze traffic patterns in the data"""
        # In a real implementation, this would use time series analysis
        # For demo purposes, we'll simulate some patterns
        
        return [
            {
                "pattern_type": "Periodic",
                "confidence": round(random.uniform(0.7, 0.95), 2),
                "details": "Regular communication pattern detected",
                "interval": f"{random.randint(5, 30)} minutes"
            },
            {
                "pattern_type": "Burst",
                "confidence": round(random.uniform(0.6, 0.9), 2),
                "details": "Periodic traffic spikes detected",
                "frequency": f"{random.randint(1, 6)} per hour"
            }
        ]
    
    def _analyze_connections(self, data):
        """Analyze connection patterns in the data"""
        # Count unique source and destination IPs
        source_ips = set()
        destination_ips = set()
        connections = set()
        
        for item in data:
            src_ip = item.get('source_ip')
            dst_ip = item.get('destination_ip')
            
            if src_ip:
                source_ips.add(src_ip)
            if dst_ip:
                destination_ips.add(dst_ip)
            if src_ip and dst_ip:
                connections.add((src_ip, dst_ip))
        
        # Top source IPs
        src_ip_counter = Counter([item.get('source_ip') for item in data if item.get('source_ip')])
        top_sources = [{"ip": ip, "count": count} for ip, count in src_ip_counter.most_common(5)]
        
        # Top destination IPs
        dst_ip_counter = Counter([item.get('destination_ip') for item in data if item.get('destination_ip')])
        top_destinations = [{"ip": ip, "count": count} for ip, count in dst_ip_counter.most_common(5)]
        
        return {
            "unique_sources": len(source_ips),
            "unique_destinations": len(destination_ips),
            "unique_connections": len(connections),
            "top_sources": top_sources,
            "top_destinations": top_destinations
        }