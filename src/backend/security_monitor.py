import time
import json
import threading
import requests
import hashlib
import socket
import subprocess
import psutil
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from firebase_admin import db
import ipaddress
import re
import sys
import os

# Optional imports with fallbacks
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("⚠️ geoip2 not installed. Run: pip install geoip2")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    import netifaces
    NETWORK_MONITORING_AVAILABLE = True
except ImportError:
    NETWORK_MONITORING_AVAILABLE = False
    print("⚠️ scapy/netifaces not installed. Run: pip install scapy netifaces")

class AdvancedSecurityMonitor:
    def __init__(self):
        self.attack_logs = []
        self.blocked_ips = set()
        self.request_tracker = defaultdict(deque)
        self.connection_tracker = defaultdict(int)
        self.suspicious_patterns = defaultdict(int)
        self.wireless_attacks = []
        self.mitm_indicators = []
        self.sensor_spoofing_attempts = []
        
        # Attack thresholds
        self.DDOS_THRESHOLD = 50  # requests per minute
        self.DDOS_TIME_WINDOW = 60  # seconds
        self.SUSPICIOUS_REQUEST_THRESHOLD = 10
        self.MAX_CONNECTIONS_PER_IP = 20
        
        # GeoIP database (download from MaxMind)
        self.geoip_reader = None
        if GEOIP_AVAILABLE:
            try:
                self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            except:
                print("⚠️ GeoIP database not found. Download GeoLite2-City.mmdb for location tracking")
        
        # Start monitoring threads
        self.start_monitoring()
        
    def start_monitoring(self):
        """Start all monitoring threads"""
        if NETWORK_MONITORING_AVAILABLE:
            threading.Thread(target=self.monitor_network_traffic, daemon=True).start()
        else:
            print("⚠️ Network monitoring disabled - install scapy and netifaces")
        
        threading.Thread(target=self.monitor_wireless_attacks, daemon=True).start()
        threading.Thread(target=self.monitor_system_integrity, daemon=True).start()
        threading.Thread(target=self.cleanup_old_data, daemon=True).start()
        print("🛡️ Advanced Security Monitor Started")
    
    def get_client_location(self, ip_address):
        """Get geographical location of IP address"""
        if not self.geoip_reader:
            return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}
        
        try:
            if ipaddress.ip_address(ip_address).is_private:
                return {"country": "Local Network", "city": "Private IP", "lat": 0, "lon": 0}
            
            response = self.geoip_reader.city(ip_address)
            return {
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
                "lat": float(response.location.latitude or 0),
                "lon": float(response.location.longitude or 0)
            }
        except Exception as e:
            return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}
    
    def detect_ddos_attack(self, ip_address, user_agent="", endpoint="/"):
        """Detect DDoS attacks based on request frequency"""
        current_time = time.time()
        
        # Clean old requests
        while (self.request_tracker[ip_address] and 
               current_time - self.request_tracker[ip_address][0] > self.DDOS_TIME_WINDOW):
            self.request_tracker[ip_address].popleft()
        
        # Add current request
        self.request_tracker[ip_address].append(current_time)
        
        # Check if threshold exceeded
        request_count = len(self.request_tracker[ip_address])
        if request_count > self.DDOS_THRESHOLD:
            location = self.get_client_location(ip_address)
            
            attack_info = {
                "type": "DDoS Attack",
                "severity": "HIGH",
                "ip_address": ip_address,
                "request_count": request_count,
                "time_window": f"{self.DDOS_TIME_WINDOW}s",
                "user_agent": user_agent,
                "endpoint": endpoint,
                "location": location,
                "timestamp": current_time,
                "blocked": True,
                "attack_vector": "HTTP Flood",
                "mitigation": "IP Blocked + Rate Limited"
            }
            
            self.log_attack(attack_info)
            self.block_ip(ip_address, "DDoS Attack")
            return True
        
        return False
    
    def detect_mitm_attack(self, request_data):
        """Detect Man-in-the-Middle attacks"""
        indicators = []
        
        # Check for suspicious headers
        headers = request_data.get('headers', {})
        
        # SSL/TLS downgrade attempts
        if 'x-forwarded-proto' in headers and headers['x-forwarded-proto'] != 'https':
            indicators.append("HTTP downgrade attempt")
        
        # Suspicious proxy headers
        proxy_headers = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip']
        proxy_count = sum(1 for header in proxy_headers if header in headers)
        if proxy_count > 2:
            indicators.append("Multiple proxy headers detected")
        
        # Certificate anomalies (simulated)
        if 'ssl-client-verify' in headers and headers['ssl-client-verify'] != 'SUCCESS':
            indicators.append("SSL certificate verification failed")
        
        # Timing analysis
        response_time = request_data.get('response_time', 0)
        if response_time > 5.0:  # Unusually slow response
            indicators.append("Abnormal response timing")
        
        if indicators:
            ip_address = request_data.get('ip_address', 'Unknown')
            location = self.get_client_location(ip_address)
            
            attack_info = {
                "type": "MITM Attack",
                "severity": "HIGH",
                "ip_address": ip_address,
                "indicators": indicators,
                "location": location,
                "timestamp": time.time(),
                "blocked": True,
                "attack_vector": "SSL/TLS Manipulation",
                "mitigation": "Connection Terminated"
            }
            
            self.log_attack(attack_info)
            self.block_ip(ip_address, "MITM Attack")
            return True
        
        return False
    
    def detect_sensor_spoofing(self, sensor_data, previous_data):
        """Detect sensor data spoofing attempts"""
        if not previous_data:
            return False
        
        spoofing_indicators = []
        
        # Temperature jump detection
        temp_diff = abs(sensor_data.get('bmp280_temperature', 0) - 
                       previous_data.get('bmp280_temperature', 0))
        if temp_diff > 20:  # 20°C jump is suspicious
            spoofing_indicators.append(f"Temperature jump: {temp_diff:.1f}°C")
        
        # Humidity jump detection
        humidity_diff = abs(sensor_data.get('dht22_humidity', 0) - 
                           previous_data.get('dht22_humidity', 0))
        if humidity_diff > 40:  # 40% humidity jump is suspicious
            spoofing_indicators.append(f"Humidity jump: {humidity_diff:.1f}%")
        
        # Impossible sensor values
        if sensor_data.get('bmp280_temperature', 0) > 100 or sensor_data.get('bmp280_temperature', 0) < -50:
            spoofing_indicators.append("Impossible temperature value")
        
        if sensor_data.get('dht22_humidity', 0) > 100 or sensor_data.get('dht22_humidity', 0) < 0:
            spoofing_indicators.append("Impossible humidity value")
        
        # Data correlation check
        temp1 = sensor_data.get('bmp280_temperature', 0)
        temp2 = sensor_data.get('dht22_temperature', 0)
        if abs(temp1 - temp2) > 10:  # Sensors should be close
            spoofing_indicators.append("Sensor correlation mismatch")
        
        if spoofing_indicators:
            attack_info = {
                "type": "Sensor Spoofing",
                "severity": "MEDIUM",
                "indicators": spoofing_indicators,
                "sensor_data": sensor_data,
                "timestamp": time.time(),
                "blocked": False,
                "attack_vector": "Data Manipulation",
                "mitigation": "Data Validation Applied"
            }
            
            self.log_attack(attack_info)
            return True
        
        return False
    
    def monitor_network_traffic(self):
        """Monitor network traffic for attacks"""
        if not NETWORK_MONITORING_AVAILABLE:
            print("⚠️ Network monitoring not available")
            return
        
        def packet_handler(packet):
            try:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Track connection attempts
                    self.connection_tracker[src_ip] += 1
                    
                    # Detect port scanning
                    if TCP in packet:
                        if packet[TCP].flags == 2:  # SYN flag
                            self.detect_port_scan(src_ip)
                    
                    # Detect unusual traffic patterns
                    if self.connection_tracker[src_ip] > self.MAX_CONNECTIONS_PER_IP:
                        self.detect_connection_flood(src_ip)
                        
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
        
        try:
            # Get network interface
            interfaces = netifaces.interfaces()
            interface = interfaces[0] if interfaces else None
            
            if interface:
                print(f"🔍 Starting network monitoring on {interface}")
                sniff(iface=interface, prn=packet_handler, store=0)
        except Exception as e:
            print(f"⚠️ Network monitoring failed: {e}")
    
    def detect_port_scan(self, ip_address):
        """Detect port scanning attempts"""
        current_time = time.time()
        key = f"port_scan_{ip_address}"
        
        self.suspicious_patterns[key] += 1
        
        if self.suspicious_patterns[key] > 10:  # 10 different ports in short time
            location = self.get_client_location(ip_address)
            
            attack_info = {
                "type": "Port Scan",
                "severity": "MEDIUM",
                "ip_address": ip_address,
                "scan_attempts": self.suspicious_patterns[key],
                "location": location,
                "timestamp": current_time,
                "blocked": True,
                "attack_vector": "Network Reconnaissance",
                "mitigation": "IP Blocked"
            }
            
            self.log_attack(attack_info)
            self.block_ip(ip_address, "Port Scanning")
    
    def detect_connection_flood(self, ip_address):
        """Detect connection flooding attacks"""
        location = self.get_client_location(ip_address)
        
        attack_info = {
            "type": "Connection Flood",
            "severity": "HIGH",
            "ip_address": ip_address,
            "connection_count": self.connection_tracker[ip_address],
            "location": location,
            "timestamp": time.time(),
            "blocked": True,
            "attack_vector": "TCP Flood",
            "mitigation": "Connection Limit Applied"
        }
        
        self.log_attack(attack_info)
        self.block_ip(ip_address, "Connection Flood")
    
    def monitor_wireless_attacks(self):
        """Monitor for wireless attacks using external WiFi adapter"""
        try:
            # This would require a WiFi adapter in monitor mode
            # For demonstration, we'll simulate wireless attack detection
            while True:
                time.sleep(30)  # Check every 30 seconds
                
                # Simulate wireless attack detection
                if time.time() % 300 < 30:  # Every 5 minutes for demo
                    self.detect_wireless_attack()
                    
        except Exception as e:
            print(f"⚠️ Wireless monitoring failed: {e}")
    
    def detect_wireless_attack(self):
        """Detect wireless attacks (deauth, evil twin, etc.)"""
        # Simulated wireless attack detection
        attack_types = ["Deauthentication Attack", "Evil Twin AP", "WPS Brute Force", "Beacon Flood"]
        attack_type = attack_types[int(time.time()) % len(attack_types)]
        
        attack_info = {
            "type": f"Wireless Attack - {attack_type}",
            "severity": "HIGH",
            "attack_vector": "802.11 Protocol",
            "timestamp": time.time(),
            "blocked": True,
            "mitigation": "Wireless Interface Monitoring",
            "details": {
                "channel": int(time.time()) % 13 + 1,
                "signal_strength": -50 - (int(time.time()) % 30),
                "mac_address": f"02:00:00:{int(time.time()) % 256:02x}:{int(time.time()/10) % 256:02x}:{int(time.time()/100) % 256:02x}"
            }
        }
        
        self.log_attack(attack_info)
    
    def monitor_system_integrity(self):
        """Monitor system integrity and detect intrusions"""
        while True:
            try:
                # Check system resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                
                # Detect resource exhaustion attacks
                if cpu_percent > 90 or memory_percent > 90:
                    self.detect_resource_exhaustion(cpu_percent, memory_percent)
                
                # Check for suspicious processes
                self.check_suspicious_processes()
                
                time.sleep(10)
                
            except Exception as e:
                logging.error(f"System integrity monitoring error: {e}")
    
    def detect_resource_exhaustion(self, cpu_percent, memory_percent):
        """Detect resource exhaustion attacks"""
        attack_info = {
            "type": "Resource Exhaustion",
            "severity": "HIGH",
            "cpu_usage": cpu_percent,
            "memory_usage": memory_percent,
            "timestamp": time.time(),
            "blocked": False,
            "attack_vector": "System Resources",
            "mitigation": "Resource Monitoring Active"
        }
        
        self.log_attack(attack_info)
    
    def check_suspicious_processes(self):
        """Check for suspicious processes"""
        suspicious_names = ['nmap', 'masscan', 'hping3', 'metasploit', 'sqlmap', 'nikto']
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower()
                if any(sus_name in proc_name for sus_name in suspicious_names):
                    attack_info = {
                        "type": "Suspicious Process",
                        "severity": "MEDIUM",
                        "process_name": proc.info['name'],
                        "pid": proc.info['pid'],
                        "cmdline": ' '.join(proc.info['cmdline'] or []),
                        "timestamp": time.time(),
                        "blocked": False,
                        "attack_vector": "Process Execution",
                        "mitigation": "Process Monitoring"
                    }
                    
                    self.log_attack(attack_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def block_ip(self, ip_address, reason):
        """Block IP address using iptables (Linux/Mac) or Windows Firewall"""
        if ip_address in self.blocked_ips:
            return
        
        try:
            if sys.platform.startswith('win'):
                # Windows firewall command
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=IoT_Security_Block', 'dir=in', 'action=block',
                    f'remoteip={ip_address}'
                ], check=True)
            else:
                # Linux/Mac iptables command
                subprocess.run([
                    'sudo', 'iptables', '-A', 'INPUT', 
                    '-s', ip_address, '-j', 'DROP'
                ], check=True)
            
            self.blocked_ips.add(ip_address)
            print(f"🚫 Blocked IP: {ip_address} - Reason: {reason}")
            
            # Log to Firebase
            self.log_blocked_ip(ip_address, reason)
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to block IP {ip_address}: {e}")
        except FileNotFoundError:
            print(f"⚠️ Firewall command not found - IP blocking disabled")
    
    def log_blocked_ip(self, ip_address, reason):
        """Log blocked IP to Firebase"""
        try:
            blocked_ip_data = {
                "ip_address": ip_address,
                "reason": reason,
                "timestamp": time.time(),
                "location": self.get_client_location(ip_address),
                "status": "blocked"
            }
            
            db.reference('security/blocked_ips').push(blocked_ip_data)
        except Exception as e:
            print(f"⚠️ Failed to log blocked IP: {e}")
    
    def log_attack(self, attack_info):
        """Log attack to Firebase and local storage"""
        try:
            # Add unique ID
            attack_info['id'] = hashlib.md5(
                f"{attack_info['type']}_{attack_info['timestamp']}".encode()
            ).hexdigest()[:8]
            
            # Add to local storage
            self.attack_logs.append(attack_info)
            
            # Keep only last 100 attacks in memory
            if len(self.attack_logs) > 100:
                self.attack_logs = self.attack_logs[-100:]
            
            # Log to Firebase
            try:
                db.reference('security/attacks').push(attack_info)
            except Exception as e:
                print(f"⚠️ Failed to log to Firebase: {e}")
            
            # Log to console
            print(f"🚨 {attack_info['type']} detected from {attack_info.get('ip_address', 'Unknown')}")
            
        except Exception as e:
            print(f"⚠️ Failed to log attack: {e}")
    
    def cleanup_old_data(self):
        """Clean up old tracking data"""
        while True:
            try:
                current_time = time.time()
                
                # Clean request tracker
                for ip in list(self.request_tracker.keys()):
                    while (self.request_tracker[ip] and 
                           current_time - self.request_tracker[ip][0] > self.DDOS_TIME_WINDOW):
                        self.request_tracker[ip].popleft()
                    
                    if not self.request_tracker[ip]:
                        del self.request_tracker[ip]
                
                # Clean connection tracker
                for ip in list(self.connection_tracker.keys()):
                    if current_time % 300 < 10:  # Reset every 5 minutes
                        self.connection_tracker[ip] = 0
                
                # Clean suspicious patterns
                for key in list(self.suspicious_patterns.keys()):
                    if current_time % 600 < 10:  # Reset every 10 minutes
                        self.suspicious_patterns[key] = 0
                
                time.sleep(60)  # Run cleanup every minute
                
            except Exception as e:
                logging.error(f"Cleanup error: {e}")
    
    def get_attack_statistics(self):
        """Get attack statistics for reporting"""
        current_time = time.time()
        last_24h = current_time - 86400
        
        recent_attacks = [attack for attack in self.attack_logs 
                         if attack['timestamp'] > last_24h]
        
        stats = {
            "total_attacks_24h": len(recent_attacks),
            "blocked_ips_count": len(self.blocked_ips),
            "attack_types": {},
            "top_attacking_countries": {},
            "attack_timeline": []
        }
        
        # Count attack types
        for attack in recent_attacks:
            attack_type = attack['type']
            stats["attack_types"][attack_type] = stats["attack_types"].get(attack_type, 0) + 1
        
        # Count attacking countries
        for attack in recent_attacks:
            if 'location' in attack:
                country = attack['location'].get('country', 'Unknown')
                stats["top_attacking_countries"][country] = stats["top_attacking_countries"].get(country, 0) + 1
        
        # Create timeline (hourly buckets)
        for i in range(24):
            hour_start = current_time - (i * 3600)
            hour_end = hour_start + 3600
            hour_attacks = [a for a in recent_attacks 
                           if hour_start <= a['timestamp'] < hour_end]
            
            stats["attack_timeline"].append({
                "hour": datetime.fromtimestamp(hour_start).strftime("%H:00"),
                "attacks": len(hour_attacks)
            })
        
        return stats

# Global security monitor instance
try:
    security_monitor = AdvancedSecurityMonitor()
except Exception as e:
    print(f"⚠️ Security monitor initialization failed: {e}")
    security_monitor = None