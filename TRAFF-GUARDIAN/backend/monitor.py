from scapy.all import sniff
from typing import Dict, Any, Optional
import time
import logging
import threading
import random
from datetime import datetime

class NetworkMonitor:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        self.active = False
        self.packet_counter = 0
        self.start_time = None
        self.stop_event = threading.Event()
        
        # For demo mode without actual packet capture
        self.demo_mode = False
    
    def process_packet(self, packet: Any) -> None:
        """Process a single packet and store relevant information."""
        try:
            self.packet_counter += 1
            
            if packet.haslayer("IP"):
                packet_data = {
                    "src_ip": packet["IP"].src,
                    "dst_ip": packet["IP"].dst,
                    "protocol": packet["IP"].proto,
                    "size": len(packet),
                    "flags": str(packet.flags) if hasattr(packet, 'flags') else '',
                    "additional_data": {
                        "time": time.time(),
                        "summary": packet.summary()
                    }
                }
                self.db_manager.log_packet(packet_data)
                
                # Occasionally generate security alerts for demo purposes
                if random.random() < 0.1:  # 10% chance
                    self._generate_demo_security_alert(packet_data)
                    
                # Occasionally generate anomalies for demo purposes
                if random.random() < 0.05:  # 5% chance
                    self._generate_demo_anomaly(packet_data)
        
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def start_monitoring(self, packet_count: int = 100, duration: int = 0) -> None:
        """Start monitoring network traffic."""
        try:
            if self.active:
                self.logger.info("Monitoring already active, restarting...")
                self.stop_monitoring()
            
            self.active = True
            self.packet_counter = 0
            self.start_time = time.time()
            self.stop_event.clear()
            
            self.logger.info(f"Starting network monitoring for {packet_count} packets")
            
            if self.demo_mode:
                # Start demo thread for testing without actual network traffic
                threading.Thread(
                    target=self._demo_packet_generator,
                    args=(packet_count, duration),
                    daemon=True
                ).start()
                return
            
            # For actual packet capture
            timeout = duration if duration > 0 else None
            
            def stop_filter(packet):
                return self.stop_event.is_set()
            
            # Start in a separate thread to not block
            threading.Thread(
                target=self._sniff_thread,
                args=(packet_count, timeout, stop_filter),
                daemon=True
            ).start()
            
        except Exception as e:
            self.logger.error(f"Error in network monitoring: {e}")
            self.active = False
    
    def _sniff_thread(self, packet_count, timeout, stop_filter):
        """Run the packet sniffer in a separate thread"""
        try:
            sniff(
                prn=self.process_packet,
                store=False,
                count=packet_count,
                timeout=timeout,
                stop_filter=stop_filter
            )
        except Exception as e:
            self.logger.error(f"Error in sniff thread: {e}")
        finally:
            self.active = False
            self.logger.info("Network monitoring stopped")
    
    def stop_monitoring(self):
        """Stop the current monitoring session"""
        if self.active:
            self.logger.info("Stopping network monitoring...")
            self.stop_event.set()
            self.active = False
    
    def get_monitoring_status(self):
        """Get the current status of monitoring"""
        if not self.active:
            return {
                "active": False,
                "packets_captured": self.packet_counter,
                "duration": 0
            }
        
        current_time = time.time()
        duration = current_time - self.start_time if self.start_time else 0
        
        return {
            "active": True,
            "packets_captured": self.packet_counter,
            "duration": round(duration, 2),
            "packets_per_second": round(self.packet_counter / duration, 2) if duration > 0 else 0
        }
    
    def _generate_demo_security_alert(self, packet_data):
        """Generate a demo security alert for testing"""
        threat_types = [
            "Intrusion Attempt", 
            "Suspicious Traffic", 
            "Port Scan", 
            "DDoS Attempt", 
            "Data Exfiltration"
        ]
        
        severities = ["Low", "Medium", "High", "Critical"]
        
        alert = {
            "type": random.choice(threat_types),
            "source_ip": packet_data["src_ip"],
            "severity": random.choice(severities),
            "timestamp": datetime.now().isoformat(),
            "details": f"Suspicious traffic from {packet_data['src_ip']} to {packet_data['dst_ip']}"
        }
        
        self.db_manager.log_security_alert(alert)
    
    def _generate_demo_anomaly(self, packet_data):
        """Generate a demo anomaly for testing"""
        anomaly_types = [
            "Traffic Spike",
            "Unusual Port Activity",
            "Protocol Anomaly",
            "Connection Pattern",
            "Data Volume Anomaly"
        ]
        
        severities = ["Low", "Medium", "High"]
        
        metrics = [
            "Bandwidth Usage",
            "Connection Count",
            "Packet Size",
            "Protocol Distribution",
            "Destination Distribution"
        ]
        
        anomaly = {
            "type": random.choice(anomaly_types),
            "affected_metric": random.choice(metrics),
            "severity": random.choice(severities),
            "timestamp": datetime.now().isoformat(),
            "details": f"Anomalous behavior detected in traffic from {packet_data['src_ip']}"
        }
        
        self.db_manager.log_anomaly(anomaly)
    
    def _demo_packet_generator(self, packet_count, duration):
        """Generate fake packets for demo mode"""
        self.logger.info("Starting demo packet generator")
        
        try:
            packet_interval = 0.1  # seconds between packets
            packets_generated = 0
            start_time = time.time()
            max_duration = duration if duration > 0 else float('inf')
            
            while (
                packets_generated < packet_count and 
                time.time() - start_time < max_duration and
                not self.stop_event.is_set()
            ):
                # Generate a fake packet
                src_ip = f"192.168.1.{random.randint(1, 254)}"
                dst_ip = f"10.0.0.{random.randint(1, 254)}"
                
                protocols = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP"
                }
                protocol = random.choice(list(protocols.keys()))
                
                packet_data = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "size": random.randint(64, 1500),
                    "flags": "",
                    "additional_data": {
                        "time": time.time(),
                        "summary": f"{src_ip} > {dst_ip} {protocols[protocol]}"
                    }
                }
                
                # Process the fake packet
                self.packet_counter += 1
                self.db_manager.log_packet(packet_data)
                
                # Occasionally generate security alerts and anomalies
                if random.random() < 0.1:
                    self._generate_demo_security_alert(packet_data)
                
                if random.random() < 0.05:
                    self._generate_demo_anomaly(packet_data)
                
                packets_generated += 1
                
                # Sleep for the packet interval
                time.sleep(packet_interval)
            
            self.active = False
            self.logger.info(f"Demo packet generator completed: {packets_generated} packets generated")
            
        except Exception as e:
            self.logger.error(f"Error in demo packet generator: {e}")
            self.active = False