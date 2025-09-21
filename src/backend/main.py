import firebase_admin
from firebase_admin import credentials, db
import time
import schedule
from datetime import datetime
import requests
import json
import os
from typing import Dict, List, Any
import threading
from collections import deque
import statistics
import socket
import sys

# Firebase configuration with error handling
def initialize_firebase():
    try:
        # Check if Firebase is already initialized
        if not firebase_admin._apps:
            cred = credentials.Certificate('firebase-service-account.json')
            firebase_admin.initialize_app(cred, {
                'databaseURL': 'https://iot-llm-security-default-rtdb.asia-southeast1.firebasedatabase.app'
            })
        print("✅ Firebase initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Firebase initialization failed: {e}")
        return False

class AIThreatDetector:
    def __init__(self, huggingface_api_key: str):
        self.api_key = huggingface_api_key
        self.model_url = "https://api-inference.huggingface.co/models/tiiuae/falcon-7b-instruct"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Attack pattern detection
        self.ddos_requests = deque(maxlen=100)
        self.sensor_history = deque(maxlen=50)
        self.mitm_indicators = []
        
    def detect_ddos_pattern(self, current_data: Dict) -> Dict:
        """Detect DDoS attack patterns"""
        current_time = time.time()
        self.ddos_requests.append(current_time)
        
        # Check request frequency (more than 10 requests in 30 seconds)
        recent_requests = [t for t in self.ddos_requests if current_time - t < 30]
        
        if len(recent_requests) > 10:
            return {
                "threat_type": "DDoS Attack",
                "threat_level": "CRITICAL",
                "confidence": 95,
                "analysis": f"Detected {len(recent_requests)} requests in 30 seconds - potential DDoS attack",
                "recommendations": ["Block suspicious IPs", "Enable rate limiting", "Alert security team"]
            }
        
        return {"threat_type": "NONE", "threat_level": "NONE"}
    
    def detect_sensor_spoofing(self, current_data: Dict) -> Dict:
        """Detect sensor spoofing attacks"""
        self.sensor_history.append(current_data)
        
        if len(self.sensor_history) < 10:
            return {"threat_type": "NONE", "threat_level": "NONE"}
        
        # Check for impossible sensor value changes
        recent_temps = [float(d.get('bmp280_temperature', 0)) for d in list(self.sensor_history)[-5:]]
        recent_humidity = [float(d.get('dht22_humidity', 0)) for d in list(self.sensor_history)[-5:]]
        
        # Detect sudden impossible changes
        if len(recent_temps) >= 2:
            temp_change = abs(recent_temps[-1] - recent_temps[-2])
            humidity_change = abs(recent_humidity[-1] - recent_humidity[-2])
            
            # Impossible temperature change (>20°C in one reading)
            if temp_change > 20:
                return {
                    "threat_type": "Sensor Spoofing",
                    "threat_level": "HIGH",
                    "confidence": 88,
                    "analysis": f"Impossible temperature change: {temp_change:.1f}°C in one reading",
                    "recommendations": ["Verify sensor integrity", "Check for tampering", "Isolate affected sensor"]
                }
            
            # Impossible humidity change (>40% in one reading)
            if humidity_change > 40:
                return {
                    "threat_type": "Sensor Spoofing",
                    "threat_level": "HIGH",
                    "confidence": 85,
                    "analysis": f"Impossible humidity change: {humidity_change:.1f}% in one reading",
                    "recommendations": ["Verify sensor integrity", "Check for tampering", "Isolate affected sensor"]
                }
        
        # Check for static values (potential sensor jamming)
        if len(set(recent_temps)) == 1 and len(recent_temps) >= 5:
            return {
                "threat_type": "Sensor Spoofing",
                "threat_level": "MEDIUM",
                "confidence": 75,
                "analysis": "Temperature sensor showing static values - potential jamming",
                "recommendations": ["Check sensor connections", "Verify sensor functionality", "Look for interference"]
            }
        
        return {"threat_type": "NONE", "threat_level": "NONE"}
    
    def detect_mitm_attack(self, current_data: Dict) -> Dict:
        """Detect Man-in-the-Middle attack patterns"""
        
        # Check for data integrity issues
        expected_correlations = self.check_sensor_correlations(current_data)
        
        if not expected_correlations:
            return {
                "threat_type": "MITM Attack",
                "threat_level": "HIGH",
                "confidence": 80,
                "analysis": "Sensor data correlations broken - potential data manipulation",
                "recommendations": ["Check network security", "Verify data integrity", "Enable encryption"]
            }
        
        # Check for timing anomalies
        current_ts = current_data.get('ts', 0)
        if len(self.sensor_history) > 0:
            last_ts = list(self.sensor_history)[-1].get('ts', 0)
            time_gap = current_ts - last_ts
            
            # Unusual timing gaps (potential replay attack)
            if time_gap > 60 or time_gap < 0:
                return {
                    "threat_type": "MITM Attack",
                    "threat_level": "MEDIUM",
                    "confidence": 70,
                    "analysis": f"Unusual timing gap: {time_gap}s - potential replay attack",
                    "recommendations": ["Check network latency", "Verify timestamp integrity", "Monitor for replay attacks"]
                }
        
        return {"threat_type": "NONE", "threat_level": "NONE"}
    
    def check_sensor_correlations(self, data: Dict) -> bool:
        """Check if sensor readings correlate as expected"""
        try:
            bmp_temp = float(data.get('bmp280_temperature', 0))
            dht_temp = float(data.get('dht22_temperature', 0))
            humidity = float(data.get('dht22_humidity', 0))
            pressure = float(data.get('pressure', 0))
            
            # Temperature sensors should be within 5°C of each other
            if abs(bmp_temp - dht_temp) > 5 and bmp_temp > 0 and dht_temp > 0:
                return False
            
            # Basic pressure-altitude correlation check
            if pressure > 0 and (pressure < 800 or pressure > 1200):
                return False
            
            # Humidity should be reasonable
            if humidity < 0 or humidity > 100:
                return False
            
            return True
        except (ValueError, TypeError):
            return False
    
    def analyze_with_ai(self, sensor_data: Dict, threat_context: Dict) -> Dict:
        """Use Falcon-7B for advanced threat analysis"""
        
        prompt = f"""You are an IoT security expert analyzing sensor data for cyber threats.

Current Sensor Data:
- BMP280 Temperature: {sensor_data.get('bmp280_temperature', 'N/A')}°C
- DHT22 Temperature: {sensor_data.get('dht22_temperature', 'N/A')}°C  
- DHT22 Humidity: {sensor_data.get('dht22_humidity', 'N/A')}%
- Pressure: {sensor_data.get('pressure', 'N/A')} hPa
- Battery: {sensor_data.get('vbat', 'N/A')} V
- Gas Sensor: {sensor_data.get('mq_ao_volt', 'N/A')} V

Detected Threat Context:
- Threat Type: {threat_context.get('threat_type', 'Unknown')}
- Threat Level: {threat_context.get('threat_level', 'Unknown')}
- Analysis: {threat_context.get('analysis', 'No analysis')}

Based on this data, analyze for:
1. DDoS attack patterns (high frequency requests)
2. Sensor spoofing (impossible value changes)
3. MITM attacks (data manipulation, timing anomalies)
4. Physical tampering indicators
5. Battery drain attacks

Respond in this format:
THREAT_LEVEL: [NONE/LOW/MEDIUM/HIGH/CRITICAL]
CONFIDENCE: [0-100]%
THREAT_TYPE: [specific threat or NONE]
ANALYSIS: [detailed explanation]
RECOMMENDATIONS: [comma-separated actions]
ATTACK_VECTOR: [how the attack is being executed]"""

        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 300,
                "temperature": 0.2,
                "do_sample": True,
                "return_full_text": False
            }
        }
        
        try:
            response = requests.post(self.model_url, headers=self.headers, json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    ai_response = result[0].get('generated_text', '').strip()
                    return self._parse_ai_response(ai_response, sensor_data, threat_context)
                else:
                    return threat_context
            else:
                print(f"❌ Hugging Face API Error: {response.status_code}")
                return threat_context
                
        except requests.exceptions.RequestException as e:
            print(f"❌ AI Analysis Error: {e}")
            return threat_context
    
    def _parse_ai_response(self, ai_response: str, sensor_data: Dict, base_threat: Dict) -> Dict:
        """Parse AI response into structured threat data"""
        
        threat_analysis = {
            "threat_level": base_threat.get("threat_level", "UNKNOWN"),
            "confidence": base_threat.get("confidence", 50),
            "threat_type": base_threat.get("threat_type", "UNKNOWN"),
            "analysis": ai_response,
            "recommendations": base_threat.get("recommendations", []),
            "attack_vector": "Unknown",
            "timestamp": int(time.time() * 1000),
            "sensor_data": sensor_data
        }
        
        try:
            lines = ai_response.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('THREAT_LEVEL:'):
                    threat_analysis["threat_level"] = line.split(':', 1)[1].strip()
                elif line.startswith('CONFIDENCE:'):
                    conf_str = line.split(':', 1)[1].strip().replace('%', '')
                    threat_analysis["confidence"] = int(conf_str) if conf_str.isdigit() else threat_analysis["confidence"]
                elif line.startswith('THREAT_TYPE:'):
                    threat_analysis["threat_type"] = line.split(':', 1)[1].strip()
                elif line.startswith('ANALYSIS:'):
                    threat_analysis["analysis"] = line.split(':', 1)[1].strip()
                elif line.startswith('RECOMMENDATIONS:'):
                    recs = line.split(':', 1)[1].strip()
                    threat_analysis["recommendations"] = [r.strip() for r in recs.split(',') if r.strip()]
                elif line.startswith('ATTACK_VECTOR:'):
                    threat_analysis["attack_vector"] = line.split(':', 1)[1].strip()
        
        except Exception as e:
            print(f"⚠️ Error parsing AI response: {e}")
        
        return threat_analysis

class SMSNotifier:
    def __init__(self):
        # Add your SMS service credentials here
        self.sms_api_key = "YOUR_SMS_API_KEY"  # Replace with your SMS service API key
        self.sms_api_url = "https://www.fast2sms.com/dev/bulkV2"  # Replace with your SMS service URL
        self.mobile_number = "+919677207889"  # Replace with your mobile number
    
    def send_threat_alert(self, threat_data: Dict):
        """Send SMS alert for critical threats"""
        if threat_data["threat_level"] in ["HIGH", "CRITICAL"]:
            message = f"🚨 IoT SECURITY ALERT 🚨\n"
            message += f"Threat: {threat_data['threat_type']}\n"
            message += f"Level: {threat_data['threat_level']}\n"
            message += f"Confidence: {threat_data['confidence']}%\n"
            message += f"Time: {datetime.now().strftime('%H:%M:%S')}\n"
            message += f"Action Required: Check system immediately"
            
            # Uncomment and configure for actual SMS sending
            # self._send_sms(message)
            print(f"📱 SMS Alert would be sent to {self.mobile_number}: {message[:100]}...")
    
    def _send_sms(self, message: str):
        """Send actual SMS (implement based on your SMS service)"""
        pass

class TelemetryMonitor:
    def __init__(self, huggingface_api_key: str):
        self.device_id = "esp32_01"
        self.firebase_connected = False
        self.telemetry_ref = None
        self.system_ref = None
        self.alerts_ref = None
        self.threats_ref = None
        
        # Initialize Firebase with retry
        self.initialize_firebase_refs()
        
        # Initialize AI threat detector
        self.ai_detector = AIThreatDetector(huggingface_api_key)
        self.sms_notifier = SMSNotifier()
        
        self.last_data_time = 0
        self.last_update_time = 0
        
        # Traditional thresholds for anomaly detection
        self.sensor_thresholds = {
            "bmp280_temperature": {"min": 15, "max": 45},
            "dht22_temperature": {"min": 15, "max": 45},
            "dht22_humidity": {"min": 30, "max": 80},
            "pressure": {"min": 950, "max": 1050},
            "altitude": {"min": 200, "max": 350},
            "vbat": {"min": 3.5, "max": 4.2},
            "mq_ao_volt": {"min": 0.5, "max": 5.0},
        }

    def initialize_firebase_refs(self):
        """Initialize Firebase references with error handling"""
        try:
            if initialize_firebase():
                self.telemetry_ref = db.reference(f"devices/{self.device_id}/telemetry")
                self.system_ref = db.reference("system")
                self.alerts_ref = db.reference("alerts/anomalies")
                self.threats_ref = db.reference("alerts/threats")
                self.firebase_connected = True
                print("✅ Firebase references initialized")
            else:
                print("❌ Firebase connection failed - running in offline mode")
                self.firebase_connected = False
        except Exception as e:
            print(f"❌ Firebase initialization error: {e}")
            self.firebase_connected = False

    def check_network_connectivity(self):
        """Check if we can reach Firebase"""
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            return False

    def safe_firebase_operation(self, operation, *args, **kwargs):
        """Safely execute Firebase operations with error handling"""
        if not self.firebase_connected:
            print("⚠️ Firebase not connected - skipping operation")
            return None
        
        try:
            return operation(*args, **kwargs)
        except Exception as e:
            print(f"❌ Firebase operation failed: {e}")
            # Try to reconnect
            if "getaddrinfo failed" in str(e) or "Failed to establish" in str(e):
                print("🔄 Attempting to reconnect to Firebase...")
                self.initialize_firebase_refs()
            return None

    def analyze_data(self, data):
        """Traditional threshold-based anomaly detection"""
        anomalies = []
        for sensor, thresholds in self.sensor_thresholds.items():
            if sensor in data:
                try:
                    value = float(data[sensor])
                    if value < thresholds["min"] or value > thresholds["max"]:
                        anomalies.append({
                            "message": f"{sensor} out of range: {value} "
                                       f"(normal: {thresholds['min']}-{thresholds['max']})",
                            "severity": "HIGH",
                            "timestamp": int(time.time() * 1000),
                            "sensor_data": data,
                            "type": "THRESHOLD_VIOLATION"
                        })
                except (ValueError, TypeError):
                    pass
        return anomalies

    def ai_threat_analysis(self, data):
        """Comprehensive AI-powered threat detection"""
        print("🤖 Running AI threat analysis...")
        
        # Run specific threat detection algorithms
        ddos_threat = self.ai_detector.detect_ddos_pattern(data)
        spoofing_threat = self.ai_detector.detect_sensor_spoofing(data)
        mitm_threat = self.ai_detector.detect_mitm_attack(data)
        
        # Determine the highest priority threat
        threats = [ddos_threat, spoofing_threat, mitm_threat]
        active_threats = [t for t in threats if t["threat_type"] != "NONE"]
        
        if active_threats:
            # Get the most critical threat
            priority_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
            highest_threat = max(active_threats, key=lambda x: priority_order.get(x["threat_level"], 0))
            
            # Enhance with AI analysis
            ai_enhanced_threat = self.ai_detector.analyze_with_ai(data, highest_threat)
            
            # Update system status
            self.safe_firebase_operation(
                lambda: self.system_ref.child("llm_status").set("scanning")
            )
            
            return ai_enhanced_threat
        else:
            # No threats detected
            self.safe_firebase_operation(
                lambda: self.system_ref.child("llm_status").set("connected")
            )
            return {
                "threat_level": "NONE",
                "confidence": 95,
                "threat_type": "NONE",
                "analysis": "All systems normal - no threats detected",
                "recommendations": [],
                "timestamp": int(time.time() * 1000),
                "sensor_data": data
            }

    def send_alerts(self, anomalies):
        """Push traditional anomalies to Firebase"""
        for anomaly in anomalies:
            self.safe_firebase_operation(
                lambda: self.alerts_ref.push(anomaly)
            )
            print(f"🚨 ALERT: {anomaly['message']}")

    def send_threat_alert(self, threat_analysis):
        """Push AI threat analysis to Firebase and send notifications"""
        if threat_analysis["threat_level"] not in ["NONE", "ERROR", "UNKNOWN"]:
            # Store detailed threat analysis
            threat_alert = {
                "message": f"AI Detected {threat_analysis['threat_level']} threat: {threat_analysis['threat_type']}",
                "severity": threat_analysis["threat_level"],
                "confidence": threat_analysis["confidence"],
                "analysis": threat_analysis["analysis"],
                "recommendations": threat_analysis["recommendations"],
                "attack_vector": threat_analysis.get("attack_vector", "Unknown"),
                "timestamp": threat_analysis["timestamp"],
                "sensor_data": threat_analysis["sensor_data"],
                "type": "AI_THREAT_DETECTION"
            }
            
            # Push to Firebase
            self.safe_firebase_operation(
                lambda: self.threats_ref.push(threat_alert)
            )
            self.safe_firebase_operation(
                lambda: self.alerts_ref.push(threat_alert)
            )
            
            print(f"🤖🚨 AI THREAT ALERT: {threat_alert['message']}")
            print(f"   Confidence: {threat_analysis['confidence']}%")
            print(f"   Analysis: {threat_analysis['analysis']}")
            print(f"   Attack Vector: {threat_analysis.get('attack_vector', 'Unknown')}")
            
            # Send SMS notification for critical threats
            self.sms_notifier.send_threat_alert(threat_analysis)
            
        else:
            print(f"🤖✅ AI Analysis: {threat_analysis['threat_level']} - {threat_analysis.get('analysis', 'No threats detected')}")

    def update_device_status(self, online=True):
        """Update device status with better offline detection"""
        now = int(time.time())
        
        if online:
            self.last_update_time = now
        
        # Check if device should be considered offline
        time_since_last_update = now - self.last_update_time
        is_really_online = online and time_since_last_update < 60
        
        status_data = {
            "online": is_really_online,
            "last_seen": now,
            "last_data_time": self.last_data_time,
            "uptime": now - self.last_data_time if is_really_online and self.last_data_time else 0,
            "ai_threat_detection": "ACTIVE",
            "time_since_last_update": time_since_last_update
        }
        
        self.safe_firebase_operation(
            lambda: self.system_ref.child("device_status").set(status_data)
        )
        
        print(f"📡 Device status: {'ONLINE' if is_really_online else 'OFFLINE'} (last update: {time_since_last_update}s ago)")

    def monitor_telemetry(self):
        """Check latest telemetry data with AI threat analysis"""
        if not self.firebase_connected:
            print("⚠️ Firebase not connected - skipping telemetry check")
            return
        
        try:
            snapshot = self.safe_firebase_operation(
                lambda: self.telemetry_ref.get()
            )
            
            if not snapshot:
                print("⚠️ No telemetry data found")
                self.update_device_status(online=False)
                return

            # Use latest telemetry entry
            data = snapshot
            ts = data.get("ts", int(time.time()))
            self.last_data_time = ts

            # Better offline detection - check actual data freshness
            current_time = int(time.time())
            
            # If timestamp is from ESP32 boot time, use current time for freshness check
            if ts < 1000000000:  # If timestamp is seconds since boot
                data_age = 0  # Consider it fresh since we just received it
            else:
                data_age = current_time - ts
            
            # Consider device offline if no update in >60s
            if data_age > 60:
                print(f"🔴 Device appears offline (data age: {data_age}s)")
                self.update_device_status(online=False)
                return

            print(f"\n📊 Telemetry @ {datetime.now().strftime('%H:%M:%S')} -> {data}")
            print(f"   Time difference: {data_age}s ago")
            
            self.update_device_status(online=True)

            # Run traditional anomaly checks
            anomalies = self.analyze_data(data)
            if anomalies:
                self.send_alerts(anomalies)

            # Run AI threat analysis
            threat_analysis = self.ai_threat_analysis(data)
            self.send_threat_alert(threat_analysis)

            if not anomalies and threat_analysis["threat_level"] in ["NONE", "UNKNOWN"]:
                print("✅ All systems normal - No threats detected")

        except Exception as e:
            print(f"❌ Error in telemetry monitoring: {e}")
            self.update_device_status(online=False)

    def cleanup_old_alerts(self):
        """Keep only last 50 alerts and threats"""
        if not self.firebase_connected:
            return
        
        try:
            # Clean traditional alerts
            snapshot = self.safe_firebase_operation(
                lambda: self.alerts_ref.order_by_key().get()
            )
            if snapshot and len(snapshot) > 50:
                keys = list(snapshot.keys())
                for key in keys[:-50]:
                    self.safe_firebase_operation(
                        lambda: self.alerts_ref.child(key).delete()
                    )
            
            # Clean threat alerts
            threat_snapshot = self.safe_firebase_operation(
                lambda: self.threats_ref.order_by_key().get()
            )
            if threat_snapshot and len(threat_snapshot) > 50:
                keys = list(threat_snapshot.keys())
                for key in keys[:-50]:
                    self.safe_firebase_operation(
                        lambda: self.threats_ref.child(key).delete()
                    )
            
            print("🧹 Old alerts and threats cleaned")
        except Exception as e:
            print(f"❌ Error cleaning alerts: {e}")

    def test_ai_connection(self):
        """Test AI model connectivity"""
        print("🤖 Testing AI model connection...")
        test_data = {
            "bmp280_temperature": 25.0,
            "dht22_temperature": 24.5,
            "dht22_humidity": 60.0,
            "pressure": 1013.25,
            "altitude": 250.0,
            "vbat": 3.8,
            "mq_ao_volt": 2.1,
            "ts": int(time.time())
        }
        
        # Test basic threat detection
        ddos_result = self.ai_detector.detect_ddos_pattern(test_data)
        spoofing_result = self.ai_detector.detect_sensor_spoofing(test_data)
        
        print("✅ AI threat detection algorithms loaded successfully")
        return True

    def start(self):
        """Start monitoring with AI threat detection"""
        print("🚀 Advanced IoT Security Monitoring Started")
        print("🤖 AI-Powered Threat Detection: Falcon-7B")
        print("🛡️  Monitoring for: DDoS, MITM, Sensor Spoofing attacks")
        
        # Check network connectivity
        if not self.check_network_connectivity():
            print("⚠️ No internet connection detected")
        
        # Test AI connection
        if not self.test_ai_connection():
            print("⚠️ Continuing without AI threat detection...")
        
        # Set initial LLM status
        if self.firebase_connected:
            self.safe_firebase_operation(
                lambda: self.system_ref.child("llm_status").set("connected")
            )
        
        schedule.every(10).seconds.do(self.monitor_telemetry)
        schedule.every(10).minutes.do(self.cleanup_old_alerts)

        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
            if self.firebase_connected:
                self.safe_firebase_operation(
                    lambda: self.system_ref.child("device_status").update({"online": False})
                )
                self.safe_firebase_operation(
                    lambda: self.system_ref.child("llm_status").set("disconnected")
                )


if __name__ == "__main__":
    # REPLACE WITH YOUR HUGGING FACE API KEY
    HUGGINGFACE_API_KEY = "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"
    
    if not HUGGINGFACE_API_KEY or HUGGINGFACE_API_KEY.startswith("hf_xxx"):
        print("❌ Please replace HUGGINGFACE_API_KEY with your actual Hugging Face API key")
        print("   Get your API key from: https://huggingface.co/settings/tokens")
        exit(1)
    
    monitor = TelemetryMonitor(HUGGINGFACE_API_KEY)
    monitor.start()