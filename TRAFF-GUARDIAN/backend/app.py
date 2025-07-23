from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
from datetime import datetime
import logging
from monitor import NetworkMonitor
from database import DatabaseManager
from security import SecurityAnalyzer
from ml_analyzer import MLAnalyzer
import time
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Initialize services
db_manager = DatabaseManager()
network_monitor = NetworkMonitor(db_manager)
security_analyzer = SecurityAnalyzer()
ml_analyzer = MLAnalyzer()

# Enable demo mode for testing without real network traffic
network_monitor.demo_mode = True

@app.route('/api/start_analysis', methods=['POST'])
def start_analysis():
    """Start network traffic analysis with specified parameters"""
    try:
        data = request.json
        packet_count = int(data.get('count', 50))
        duration = int(data.get('duration', 0))  # Duration in seconds, 0 means no limit
        
        if packet_count < 1:
            return jsonify({"error": "Packet count must be positive"}), 400
        
        # Start monitoring
        network_monitor.start_monitoring(packet_count, duration)
        
        return jsonify({
            "message": f"Analysis started for {packet_count} packets",
            "status": "success"
        })
        
    except ValueError as e:
        logger.error(f"Value error in start_analysis: {str(e)}")
        return jsonify({"error": "Invalid parameters"}), 400
    except Exception as e:
        logger.error(f"Unexpected error in start_analysis: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/stop_analysis', methods=['POST'])
def stop_analysis():
    """Stop the current network analysis"""
    try:
        network_monitor.stop_monitoring()
        return jsonify({
            "message": "Analysis stopped",
            "status": "success"
        })
    except Exception as e:
        logger.error(f"Error stopping analysis: {str(e)}")
        return jsonify({"error": "Failed to stop analysis"}), 500

@app.route('/api/status', methods=['GET'])
def get_monitoring_status():
    """Get the current status of network monitoring"""
    try:
        status = network_monitor.get_monitoring_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting monitoring status: {str(e)}")
        return jsonify({"error": "Failed to get monitoring status"}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get network statistics"""
    try:
        stats = db_manager.get_network_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error fetching stats: {str(e)}")
        return jsonify({"error": "Failed to fetch statistics"}), 500

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Get current network metrics for dashboard"""
    try:
        metrics = db_manager.get_metrics()
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Error fetching metrics: {str(e)}")
        return jsonify({"error": "Failed to fetch metrics"}), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get security threat information"""
    try:
        alerts = db_manager.get_security_alerts()
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error fetching threats: {str(e)}")
        return jsonify({"error": "Failed to fetch threats"}), 500

@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    """Get detected network anomalies"""
    try:
        anomalies = db_manager.get_anomalies()
        return jsonify(anomalies)
    except Exception as e:
        logger.error(f"Error fetching anomalies: {str(e)}")
        return jsonify({"error": "Failed to fetch anomalies"}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts (alias for /api/threats)"""
    return get_threats()

@app.route('/api/traffic_analysis', methods=['GET'])
def get_traffic_analysis():
    """Get traffic analysis data"""
    try:
        period = request.args.get('period', 'hour')  # hour, day, week
        if period not in ['hour', 'day', 'week']:
            return jsonify({"error": "Invalid period. Use 'hour', 'day', or 'week'"}), 400
            
        analysis = db_manager.get_traffic_analysis(period)
        return jsonify(analysis)
    except Exception as e:
        logger.error(f"Error in traffic analysis: {str(e)}")
        return jsonify({"error": "Failed to analyze traffic"}), 500

@app.route('/api/analytics/status-codes', methods=['GET'])
def get_status_codes():
    """Get HTTP status code analytics"""
    try:
        status_codes = ml_analyzer.analyze_status_codes()
        return jsonify(status_codes)
    except Exception as e:
        logger.error(f"Error analyzing status codes: {str(e)}")
        return jsonify({"error": "Failed to analyze status codes"}), 500

@app.route('/api/security/overview', methods=['GET'])
def get_security_overview():
    """Get security overview information"""
    try:
        overview = security_analyzer.get_security_overview()
        return jsonify(overview)
    except Exception as e:
        logger.error(f"Error getting security overview: {str(e)}")
        return jsonify({"error": "Failed to get security overview"}), 500

@app.route('/api/security/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get vulnerability information"""
    try:
        vulnerabilities = security_analyzer.get_vulnerabilities()
        return jsonify(vulnerabilities)
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {str(e)}")
        return jsonify({"error": "Failed to get vulnerabilities"}), 500

@app.route('/api/ml/predict', methods=['GET'])
def get_prediction():
    """Get ML predictions for traffic load"""
    try:
        period = request.args.get('period', 'hour')
        prediction = ml_analyzer.predict_traffic_load(period)
        return jsonify(prediction)
    except Exception as e:
        logger.error(f"Error in ML prediction: {str(e)}")
        return jsonify({"error": "Failed to generate prediction"}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })

# Start background tasks when app starts
def run_background_tasks():
    """Run periodic background tasks"""
    logger.info("Starting background tasks")
    
    while True:
        try:
            # Run ML analysis on recent data
            recent_stats = db_manager.get_network_stats(limit=1000)
            if recent_stats:
                anomalies = ml_analyzer.detect_anomalies(recent_stats)
                if anomalies and anomalies.get('anomalies_detected', 0) > 0:
                    for anomaly in anomalies.get('anomaly_details', []):
                        db_manager.log_anomaly(anomaly)
                
                # Run security analysis
                threats = security_analyzer.analyze_threats(recent_stats)
                for threat in threats:
                    db_manager.log_security_alert(threat)
        except Exception as e:
            logger.error(f"Error in background tasks: {str(e)}")
        
        # Sleep for 5 minutes
        time.sleep(300)

if __name__ == '__main__':
    # Start background tasks in a separate thread
    background_thread = threading.Thread(target=run_background_tasks, daemon=True)
    background_thread.start()
    
    # Determine host and port
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    
    # Start the Flask app
    app.run(debug=True, host=host, port=port)