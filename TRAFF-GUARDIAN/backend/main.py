"""
Network Security Monitoring Main Entry Point
-------------------------------------------
This script initializes and starts the network security monitoring system.
"""

import logging
import threading
import time
import signal
import sys
from database import DatabaseManager
from monitor import NetworkMonitor
from security import SecurityAnalyzer
from ml_analyzer import MLAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('network_monitor.log')
    ]
)

logger = logging.getLogger(__name__)

class NetworkSecuritySystem:
    def __init__(self):
        """Initialize the network security monitoring system"""
        logger.info("Initializing Network Security Monitoring System")
        
        # Initialize components
        self.db_manager = DatabaseManager()
        self.monitor = NetworkMonitor(self.db_manager)
        self.security_analyzer = SecurityAnalyzer()
        self.ml_analyzer = MLAnalyzer()
        
        # Enable demo mode for testing without real network traffic
        self.monitor.demo_mode = True
        
        # For graceful shutdown
        self.shutdown_event = threading.Event()
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
    
    def start(self):
        """Start the network security monitoring system"""
        logger.info("Starting Network Security Monitoring System")
        
        try:
            # Start monitoring thread
            monitoring_thread = threading.Thread(
                target=self._run_monitoring_loop,
                daemon=True
            )
            monitoring_thread.start()
            
            # Start analysis thread
            analysis_thread = threading.Thread(
                target=self._run_analysis_loop,
                daemon=True
            )
            analysis_thread.start()
            
            # Start the API server in app.py
            # This is typically handled separately, not here
            
            # Wait for shutdown signal
            while not self.shutdown_event.is_set():
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"Error starting system: {e}")
            self.shutdown()
        
        logger.info("Network Security Monitoring System has been shut down")
    
    def _run_monitoring_loop(self):
        """Run the network monitoring loop"""
        logger.info("Starting network monitoring loop")
        
        try:
            while not self.shutdown_event.is_set():
                if not self.monitor.active:
                    # Start a new monitoring session
                    packet_count = 1000  # Number of packets to capture
                    duration = 300  # 5 minutes
                    
                    logger.info(f"Starting monitoring session: {packet_count} packets, {duration}s duration")
                    self.monitor.start_monitoring(packet_count, duration)
                
                # Wait a bit before checking again
                time.sleep(5)
                
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            self.shutdown_event.set()
    
    def _run_analysis_loop(self):
        """Run the security and ML analysis loop"""
        logger.info("Starting analysis loop")
        
        try:
            while not self.shutdown_event.is_set():
                # Get recent network statistics
                recent_stats = self.db_manager.get_network_stats(limit=1000)
                
                if recent_stats:
                    # Run security analysis
                    logger.info("Running security analysis")
                    threats = self.security_analyzer.analyze_threats(recent_stats)
                    
                    for threat in threats:
                        logger.warning(f"Security threat detected: {threat['type']} from {threat['source_ip']}")
                        self.db_manager.log_security_alert(threat)
                    
                    # Run ML analysis
                    logger.info("Running ML analysis")
                    anomalies = self.ml_analyzer.detect_anomalies(recent_stats)
                    
                    if anomalies and anomalies.get('anomalies_detected', 0) > 0:
                        for anomaly in anomalies.get('anomaly_details', []):
                            logger.warning(f"Anomaly detected: {anomaly['type']}")
                            self.db_manager.log_anomaly(anomaly)
                
                # Wait before the next analysis
                time.sleep(60)  # Run analysis every minute
                
        except Exception as e:
            logger.error(f"Error in analysis loop: {e}")
            self.shutdown_event.set()
    
    def handle_shutdown(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received shutdown signal: {signum}")
        self.shutdown()
    
    def shutdown(self):
        """Gracefully shut down the system"""
        logger.info("Shutting down Network Security Monitoring System")
        
        # Stop monitoring
        if self.monitor.active:
            self.monitor.stop_monitoring()
        
        # Set shutdown event
        self.shutdown_event.set()

if __name__ == "__main__":
    # Start the network security monitoring system
    system = NetworkSecuritySystem()
    system.start()