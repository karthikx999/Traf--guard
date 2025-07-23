import sqlite3
import json
from datetime import datetime, timedelta
import random
import logging

class DatabaseManager:
    def __init__(self, db_path="network_monitor.db"):
        """Initialize database connection and create tables if they don't exist"""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._create_tables()
    
    def _get_connection(self):
        """Get a database connection"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Return rows as dictionaries
            return conn
        except sqlite3.Error as e:
            self.logger.error(f"Database connection error: {e}")
            raise
    
    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Network stats table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                port INTEGER,
                packet_count INTEGER,
                byte_count INTEGER,
                additional_data TEXT
            )
            ''')
            
            # Security alerts table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                source_ip TEXT,
                severity TEXT NOT NULL,
                details TEXT,
                is_resolved INTEGER DEFAULT 0
            )
            ''')
            
            # Anomalies table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                affected_metric TEXT,
                severity TEXT NOT NULL,
                details TEXT
            )
            ''')
            
            # Traffic analysis table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                period TEXT NOT NULL,
                data TEXT NOT NULL
            )
            ''')
            
            conn.commit()
            self.logger.info("Database tables created successfully")
        except sqlite3.Error as e:
            self.logger.error(f"Error creating tables: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def log_packet(self, packet_data):
        """Log a network packet to the database"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Extract packet data
            source_ip = packet_data.get('src_ip')
            destination_ip = packet_data.get('dst_ip')
            protocol = packet_data.get('protocol')
            size = packet_data.get('size', 0)
            additional_data = json.dumps(packet_data.get('additional_data', {}))
            
            # Get current timestamp
            timestamp = datetime.now().isoformat()
            
            # Insert into network_stats table
            cursor.execute('''
            INSERT INTO network_stats (
                timestamp, source_ip, destination_ip, protocol, 
                packet_count, byte_count, additional_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, source_ip, destination_ip, protocol, 1, size, additional_data))
            
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            self.logger.error(f"Error logging packet: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def log_security_alert(self, alert_data):
        """Log a security alert to the database"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Extract alert data
            alert_type = alert_data.get('type')
            source_ip = alert_data.get('source_ip')
            severity = alert_data.get('severity')
            details = alert_data.get('details')
            timestamp = alert_data.get('timestamp') or datetime.now().isoformat()
            
            # Insert into security_alerts table
            cursor.execute('''
            INSERT INTO security_alerts (
                timestamp, type, source_ip, severity, details
            ) VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, alert_type, source_ip, severity, details))
            
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            self.logger.error(f"Error logging security alert: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def log_anomaly(self, anomaly_data):
        """Log a network anomaly to the database"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Extract anomaly data
            anomaly_type = anomaly_data.get('type')
            affected_metric = anomaly_data.get('affected_metric')
            severity = anomaly_data.get('severity')
            details = anomaly_data.get('details')
            timestamp = anomaly_data.get('timestamp') or datetime.now().isoformat()
            
            # Insert into anomalies table
            cursor.execute('''
            INSERT INTO anomalies (
                timestamp, type, affected_metric, severity, details
            ) VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, anomaly_type, affected_metric, severity, details))
            
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            self.logger.error(f"Error logging anomaly: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def save_traffic_analysis(self, period, data):
        """Save traffic analysis results to the database"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Convert data to JSON
            data_json = json.dumps(data)
            timestamp = datetime.now().isoformat()
            
            # Insert into traffic_analysis table
            cursor.execute('''
            INSERT INTO traffic_analysis (
                timestamp, period, data
            ) VALUES (?, ?, ?)
            ''', (timestamp, period, data_json))
            
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            self.logger.error(f"Error saving traffic analysis: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def get_network_stats(self, limit=100):
        """Get recent network statistics"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM network_stats
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            result = []
            for row in rows:
                item = dict(row)
                if 'additional_data' in item and item['additional_data']:
                    try:
                        item['additional_data'] = json.loads(item['additional_data'])
                    except json.JSONDecodeError:
                        pass
                result.append(item)
            
            return result
        except sqlite3.Error as e:
            self.logger.error(f"Error fetching network stats: {e}")
            return []
        finally:
            conn.close()
    
    def get_security_alerts(self, limit=50, include_resolved=False):
        """Get recent security alerts"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            query = '''
            SELECT * FROM security_alerts
            '''
            
            if not include_resolved:
                query += ' WHERE is_resolved = 0'
            
            query += '''
            ORDER BY timestamp DESC
            LIMIT ?
            '''
            
            cursor.execute(query, (limit,))
            
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            self.logger.error(f"Error fetching security alerts: {e}")
            return []
        finally:
            conn.close()
    
    def get_anomalies(self, limit=50):
        """Get recent anomalies"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM anomalies
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            self.logger.error(f"Error fetching anomalies: {e}")
            return []
        finally:
            conn.close()
    
    def get_traffic_analysis(self, period='hour'):
        """Get traffic analysis data for the specified period"""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM traffic_analysis
            WHERE period = ?
            ORDER BY timestamp DESC
            LIMIT 1
            ''', (period,))
            
            row = cursor.fetchone()
            
            if row:
                result = dict(row)
                if 'data' in result and result['data']:
                    try:
                        result['data'] = json.loads(result['data'])
                        return result['data']
                    except json.JSONDecodeError:
                        pass
            
            # If no data found or error in parsing, return sample data
            return self._generate_sample_traffic_data(period)
        except sqlite3.Error as e:
            self.logger.error(f"Error fetching traffic analysis: {e}")
            return self._generate_sample_traffic_data(period)
        finally:
            conn.close()
    
    def _generate_sample_traffic_data(self, period='hour'):
        """Generate sample traffic data when real data is not available"""
        now = datetime.now()
        data = []
        
        if period == 'hour':
            # Generate data for the last hour in 5-minute intervals
            for i in range(12):
                timestamp = (now - timedelta(minutes=i * 5)).strftime('%H:%M')
                data.append({
                    'timestamp': timestamp,
                    'value': random.randint(50, 200)
                })
        elif period == 'day':
            # Generate data for the last day in hourly intervals
            for i in range(24):
                timestamp = (now - timedelta(hours=i)).strftime('%H:00')
                data.append({
                    'timestamp': timestamp,
                    'value': random.randint(50, 200)
                })
        elif period == 'week':
            # Generate data for the last week in daily intervals
            for i in range(7):
                timestamp = (now - timedelta(days=i)).strftime('%a')
                data.append({
                    'timestamp': timestamp,
                    'value': random.randint(50, 200)
                })
        
        # Reverse to get chronological order
        data.reverse()
        
        # Generate threat distribution data
        threat_distribution = [
            {'type': 'Intrusion', 'count': random.randint(5, 20)},
            {'type': 'DDoS', 'count': random.randint(1, 10)},
            {'type': 'Malware', 'count': random.randint(3, 15)},
            {'type': 'Phishing', 'count': random.randint(8, 25)}
        ]
        
        return {
            'traffic_history': data,
            'threat_distribution': threat_distribution
        }
    
    def get_metrics(self):
        """Get current network metrics for dashboard"""
        # Get recent network statistics
        recent_stats = self.get_network_stats(limit=1000)
        
        # Calculate traffic rate (packets per second)
        now = datetime.now()
        one_minute_ago = now - timedelta(minutes=1)
        
        recent_packets = [
            stat for stat in recent_stats 
            if datetime.fromisoformat(stat['timestamp']) > one_minute_ago
        ]
        
        traffic_rate = len(recent_packets) / 60  # packets per second
        
        # Calculate average response time (mock data for now)
        avg_response_time = random.randint(20, 150)
        
        # Calculate security score (mock data for now)
        security_score = random.randint(70, 95)
        
        # Get traffic history data
        traffic_analysis = self.get_traffic_analysis('hour')
        
        return {
            'traffic_rate': round(traffic_rate, 2),
            'avg_response_time': avg_response_time,
            'security_score': security_score,
            'traffic_history': traffic_analysis.get('traffic_history', []),
            'threat_distribution': traffic_analysis.get('threat_distribution', [])
        }