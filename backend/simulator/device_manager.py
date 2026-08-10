import asyncio
import json
import random
import sys
import os
import logging
import math
from datetime import datetime
from typing import Dict, Any

# Add parent directory to path to allow direct execution
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paho.mqtt.client as mqtt

# Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_TOPIC = "iot/data"
NUMBER_OF_DEVICES = 1000
PUBLISH_INTERVAL = 10
ATTACK_PROBABILITY = 0.005  # Spontaneous attack probability

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global registry of devices for API access
DEVICES_MAP: Dict[str, 'VirtualDevice'] = {}
ACTIVE_TASKS = []

class MQTTClient:
    """Wrapper for MQTT client with reconnection support and in-memory fallback"""
    
    def __init__(self):
        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        self.connected = False
        self.in_memory = False
        
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            logger.info(f"Connected to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}")
        else:
            logger.error(f"Failed to connect to MQTT broker, return code: {rc}")
            
    def on_disconnect(self, client, userdata, rc):
        self.connected = False
        if rc != 0:
            logger.warning("Unexpected disconnection from MQTT broker")
            
    def connect(self):
        try:
            # Fast timeout for local connect to fail quick and trigger in-memory fallback
            self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=10)
            self.client.loop_start()
            return True
        except Exception as e:
            logger.warning(f"MQTT connection failed ({e}). Falling back to In-Memory Gateway Mode.")
            self.in_memory = True
            self.connected = True
            return True
            
    def publish(self, topic: str, payload: str) -> bool:
        if self.in_memory:
            # Directly invoke the bridge's payload processor in-memory
            try:
                from mqtt_bridge import process_payload
                data = json.loads(payload)
                process_payload(data)
                return True
            except Exception as e:
                logger.error(f"Failed to process in-memory payload: {e}")
                return False
                
        if not self.connected:
            logger.warning("MQTT client not connected, attempting to reconnect...")
            if not self.connect():
                return False
        try:
            self.client.publish(topic, payload)
            return True
        except Exception as e:
            logger.error(f"Failed to publish message: {e}")
            return False
            
    def disconnect(self):
        if not self.in_memory:
            self.client.loop_stop()
            self.client.disconnect()
        logger.info("Disconnected from MQTT/In-Memory Gateway")

class VirtualDevice:
    """Simulates an IoT device with realistic diurnal physics, workload thermal models, PQC energy overheads, and multi-stage stateful attacks."""
    
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.battery = random.uniform(85, 100)
        self.solar_capable = (random.random() < 0.3)  # 30% have solar panels
        self.temperature = 22.0
        self.cpu_usage = random.uniform(5, 12)
        self.memory_usage = random.uniform(128, 256)
        self.requests_per_minute = random.uniform(5, 15)
        
        # Replay protection & session caching
        # Initialize sequence_number from DB to prevent restart synchronization bugs
        from database import SessionLocal, Device
        session = SessionLocal()
        try:
            dev = session.query(Device).filter(Device.device_id == device_id).first()
            self.sequence_number = dev.last_sequence if (dev and dev.last_sequence is not None) else 0
        except Exception:
            self.sequence_number = 0
        finally:
            session.close()
            
        self.session_key = None
        self.session_kem_ciphertext = None
        self.session_packets_sent = 0
        self.session_kem_algo = None
        self.session_sig_algo = None
        self.session_start_time = None
        
        # Stateful Attack parameters
        # States: "NORMAL", "RECONNAISSANCE", "ATTACKING", "MITIGATED"
        self.state = "NORMAL"
        self.attack_type = None  # "DDoS", "Cryptojacking", "Thermal Tampering"
        self.attack_duration = 0
        self.mitigation_duration = 0
        self.selected_kem = "ML-KEM-512"
        self.selected_signature = "ML-DSA-44"
        self.sig_keys = {}
        self._init_keys()

    def _init_keys(self):
        """Generates long-term signature keypairs for both ML-DSA-44 and FN-DSA-512."""
        try:
            from pqc.pqc_oqs import PQCManager
            pqc = PQCManager()
            for sig in ["ML-DSA-44", "FN-DSA-512"]:
                self.sig_keys[sig] = pqc.generate_keypair(sig)
        except Exception as e:
            logger.error(f"Failed to generate signature keypairs for device {self.device_id}: {e}")
        
    def trigger_attack(self, attack_type: str):
        """Manually trigger an attack on this device"""
        if self.state in ["NORMAL", "RECONNAISSANCE"]:
            self.state = "ATTACKING"
            self.attack_type = attack_type
            self.attack_duration = random.randint(8, 15)
            logger.info(f"Targeted attack {attack_type} injected into {self.device_id}")
            return True
        return False
        
    def reset(self):
        """Reset device back to normal health"""
        self.state = "NORMAL"
        self.attack_type = None
        self.attack_duration = 0
        self.mitigation_duration = 0
        self.battery = 100.0
        self.cpu_usage = random.uniform(5, 12)
        self.memory_usage = random.uniform(128, 256)
        self.requests_per_minute = random.uniform(5, 15)
        self.sequence_number = 0
        self.session_key = None
        self.session_kem_ciphertext = None
        self.session_packets_sent = 0
        self.session_kem_algo = None
        self.session_sig_algo = None
        self.session_start_time = None
        
    def generate_payload(self) -> Dict[str, Any]:
        """Generate sensor data payload with diurnal cycles, thermal heating, PQC overhead, and state transitions"""
        
        # 1. Diurnal temperature cycle (peaks at 14:00, coolest at 04:00)
        now = datetime.now()
        hour = now.hour + now.minute / 60.0
        ambient_temp = 25.0 + 6.0 * math.sin((hour - 8.0) * math.pi / 12.0)
        
        # Sync selected algorithm from DB if possible to model correct battery overhead
        try:
            from database import SessionLocal, Device
            with SessionLocal() as session:
                dev = session.query(Device).filter(Device.device_id == self.device_id).first()
                if dev:
                    self.selected_kem = dev.selected_kem or "ML-KEM-512"
                    self.selected_signature = dev.selected_signature or "ML-DSA-44"
                    
                    # Check and register signature public keys in DB if missing
                    if not dev.sig_public_key_ml_dsa_44 or not dev.sig_public_key_fn_dsa_512:
                        if self.sig_keys:
                            dev.sig_public_key_ml_dsa_44 = self.sig_keys.get("ML-DSA-44", {}).get("public_key")
                            dev.sig_public_key_fn_dsa_512 = self.sig_keys.get("FN-DSA-512", {}).get("public_key")
                            session.commit()
        except Exception as e:
            logger.error(f"Error syncing device keys to database: {e}")
            
        # 2. State machine transitions and values
        if self.state == "NORMAL":
            self.cpu_usage = max(5.0, min(20.0, self.cpu_usage + random.uniform(-1.5, 1.5)))
            self.memory_usage = max(128.0, min(384.0, self.memory_usage + random.uniform(-5.0, 5.0)))
            self.requests_per_minute = max(5.0, min(25.0, self.requests_per_minute + random.uniform(-2.0, 2.0)))
            
            # Spontaneous attack transition
            if random.random() < ATTACK_PROBABILITY:
                self.state = "RECONNAISSANCE"
                self.attack_type = random.choice(["DDoS", "Cryptojacking", "Thermal Tampering"])
                self.attack_duration = random.randint(3, 5)
                
        elif self.state == "RECONNAISSANCE":
            # Scanning/probing phase: elevated requests, mild cpu
            self.cpu_usage = max(12.0, min(28.0, self.cpu_usage + random.uniform(-1.0, 2.0)))
            self.memory_usage = max(180.0, min(450.0, self.memory_usage + random.uniform(-5.0, 10.0)))
            self.requests_per_minute = max(60.0, min(140.0, self.requests_per_minute + random.uniform(-5.0, 15.0)))
            
            self.attack_duration -= 1
            if self.attack_duration <= 0:
                self.state = "ATTACKING"
                self.attack_duration = random.randint(8, 16)
                
        elif self.state == "ATTACKING":
            if self.attack_type == "DDoS":
                self.cpu_usage = round(random.uniform(80.0, 95.0), 2)
                self.memory_usage = round(random.uniform(1024.0, 2048.0), 2)
                self.requests_per_minute = round(random.uniform(2500.0, 4200.0), 2)
            elif self.attack_type == "Cryptojacking":
                self.cpu_usage = round(random.uniform(95.0, 100.0), 2)
                self.memory_usage = round(random.uniform(1500.0, 2600.0), 2)
                self.requests_per_minute = round(random.uniform(20.0, 60.0), 2)
            elif self.attack_type == "Thermal Tampering":
                self.cpu_usage = round(random.uniform(55.0, 85.0), 2)
                self.memory_usage = round(random.uniform(512.0, 1200.0), 2)
                self.requests_per_minute = round(random.uniform(30.0, 120.0), 2)
                
            self.attack_duration -= 1
            
            # Check if database auto-firewalled / blocked this device
            is_blocked = False
            try:
                from database import SessionLocal, Device
                with SessionLocal() as session:
                    dev = session.query(Device).filter(Device.device_id == self.device_id).first()
                    if dev and dev.status == "BLOCKED":
                        is_blocked = True
            except Exception:
                pass
                
            if is_blocked:
                self.state = "MITIGATED"
                self.mitigation_duration = random.randint(8, 15)
            elif self.attack_duration <= 0:
                self.state = "NORMAL"
                self.attack_type = None

        elif self.state == "MITIGATED":
            # Quarantined / Rate-limited state: cool down and drop resource usages
            self.cpu_usage = max(2.0, min(6.0, self.cpu_usage - 10.0))
            self.memory_usage = max(64.0, min(128.0, self.memory_usage - 100.0))
            self.requests_per_minute = 0.0
            
            self.mitigation_duration -= 1
            if self.mitigation_duration <= 0:
                # Try unblocking device in DB and recover
                self.state = "NORMAL"
                self.attack_type = None
                try:
                    from database import SessionLocal, Device
                    with SessionLocal() as session:
                        dev = session.query(Device).filter(Device.device_id == self.device_id).first()
                        if dev and dev.status == "BLOCKED":
                            dev.status = "ONLINE"
                            session.commit()
                            from mqtt_bridge import log_event
                            log_event("SOC", "INF", f"Device {self.device_id} firewall block expired. Restored online.")
                except Exception:
                    pass

        # 3. Workload Thermal Model (temperature gradual change with thermal inertia)
        target_heating = 0.0
        if self.state == "ATTACKING":
            if self.attack_type == "Cryptojacking":
                target_heating = 48.0
            elif self.attack_type == "Thermal Tampering":
                target_heating = 68.0
            else:
                target_heating = 22.0
        else:
            target_heating = (self.cpu_usage / 100.0) * 14.0
            
        target_temp = ambient_temp + target_heating
        self.temperature += (target_temp - self.temperature) * 0.15  # Thermal inertia
        
        # 4. Battery drain model with PQC overhead
        # NOTE ON MODEL ASSUMPTIONS:
        # These battery drain coefficients are synthetic, modeled simulation assumptions
        # representing relative energy overheads of PQC algorithms, not physically measured joules.
        pqc_drain_rates = {
            "ML-KEM-512": 0.001,
            "ML-KEM-768": 0.003,
            "FN-DSA-512": 0.005,
            "ML-DSA-44": 0.015
        }
        pqc_overhead = pqc_drain_rates.get(self.selected_kem, 0.001) + pqc_drain_rates.get(self.selected_signature, 0.001)
        
        attack_drain_factor = 1.0
        if self.state == "ATTACKING":
            attack_drain_factor = 7.0 if self.attack_type == "Cryptojacking" else 4.0
            
        drain = (0.01 + (self.cpu_usage * 0.0025) + pqc_overhead) * attack_drain_factor
        self.battery = max(0.0, self.battery - drain)
        
        # 5. Solar charging (during day hours 6:00 to 18:00)
        if self.solar_capable and (6.0 <= hour <= 18.0) and self.state != "MITIGATED":
            solar_intensity = math.sin((hour - 6.0) * math.pi / 12.0)
            charge = solar_intensity * 0.05
            self.battery = min(100.0, self.battery + charge)
            
        # 6. Check low battery shutdown
        status = "ONLINE"
        if self.battery < 5.0:
            status = "OFFLINE"
            # Solar panel charges it back to online
            if self.solar_capable and self.battery > 15.0:
                self.battery = 15.0  # limit online threshold
                
        self.sequence_number += 1
        payload = {
            "device_id": self.device_id,
            "sequence": self.sequence_number,
            "timestamp": datetime.utcnow().isoformat(),
            "temperature": round(self.temperature, 2),
            "humidity": round(max(8.0, min(95.0, 78.0 - (self.temperature - 20.0) * 1.6 + random.uniform(-4, 4))), 2),
            "battery": round(self.battery, 2),
            "cpu_usage": round(self.cpu_usage, 2),
            "memory_usage": round(self.memory_usage, 2),
            "requests_per_minute": round(self.requests_per_minute, 2),
            "status": status
        }
        
        if self.state == "ATTACKING":
            payload.update({
                "attack": True,
                "attack_type": self.attack_type
            })
        elif self.state == "RECONNAISSANCE":
            payload.update({
                "attack": True,
                "attack_type": "Port Scanning"
            })
            
        return payload

async def device_loop(device: VirtualDevice, mqtt_client: MQTTClient):
    """Async loop for each virtual device"""
    while True:
        try:
            payload = device.generate_payload()
            
            # If device is battery-depleted, skip publishing
            if payload.get("status") == "OFFLINE":
                await asyncio.sleep(PUBLISH_INTERVAL)
                continue
                
            # Encrypt and sign payload using selected PQC algorithms
            try:
                from pqc.pqc_secure_channel import encrypt_and_sign_payload
                sig_algo = device.selected_signature or "ML-DSA-44"
                kem_algo = device.selected_kem or "ML-KEM-512"
                
                # Ensure keys are loaded
                if sig_algo not in device.sig_keys:
                    raise ValueError(f"Device missing signature keys for algorithm: {sig_algo}")
                    
                sig_private_key = device.sig_keys[sig_algo]["private_key"]
                
                # Session key caching, rotation, and renegotiation on algorithm switch.
                # Rekeying policy justifies PFS security in constrained IoT environments:
                # - Maximum 20 messages per session to limit plaintext exposure under a single symmetric key.
                # - Maximum 180 seconds (3 minutes) lifetime to ensure keys expire even with delayed/dropped packets.
                import time as pytime
                session_expired = False
                if device.session_start_time is not None:
                    if pytime.time() - device.session_start_time >= 180.0:
                        session_expired = True
                        
                if device.session_packets_sent >= 20:
                    session_expired = True

                if (device.session_key is not None and 
                    not session_expired and
                    kem_algo == device.session_kem_algo and 
                    sig_algo == device.session_sig_algo):
                    
                    secured_payload = encrypt_and_sign_payload(
                        device_id=device.device_id,
                        payload_dict=payload,
                        kem_algo=kem_algo,
                        sig_algo=sig_algo,
                        device_sig_private_key_hex=sig_private_key,
                        session_key=device.session_key,
                        session_kem_ciphertext_hex=device.session_kem_ciphertext
                    )
                    device.session_packets_sent += 1
                else:
                    logger.info(f"Reconfiguring/negotiating PQC session key for device {device.device_id} ({kem_algo} + {sig_algo})")
                    secured_payload = encrypt_and_sign_payload(
                        device_id=device.device_id,
                        payload_dict=payload,
                        kem_algo=kem_algo,
                        sig_algo=sig_algo,
                        device_sig_private_key_hex=sig_private_key
                    )
                    device.session_key = bytes.fromhex(secured_payload["session_key"])
                    device.session_kem_ciphertext = secured_payload["kem_ciphertext"]
                    device.session_kem_algo = kem_algo
                    device.session_sig_algo = sig_algo
                    device.session_packets_sent = 1
                    device.session_start_time = pytime.time()
                
                # Pop session_key local metadata
                secured_payload.pop("session_key", None)
                
                # Attach public key for signature verification
                secured_payload["sig_public_key"] = device.sig_keys[sig_algo]["public_key"]
                payload_to_send = secured_payload
                
            except Exception as e:
                logger.error(f"PQC SECURE CHANNEL FAILURE on device {device.device_id}: {e} - ABORTING telemetry transmission.")
                # DO NOT SEND plaintext telemetry!
                await asyncio.sleep(PUBLISH_INTERVAL)
                continue
                
            success = mqtt_client.publish(MQTT_TOPIC, json.dumps(payload_to_send))
            await asyncio.sleep(PUBLISH_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in device {device.device_id}: {e}")
            await asyncio.sleep(2)

async def start_simulator_background():
    """Starts the simulation loop as a background task"""
    global ACTIVE_TASKS
    
    logger.info("Initializing QuantumShield-IoT Simulation Task...")
    mqtt_client = MQTTClient()
    mqtt_client.connect()
    
    # Initialize devices and pre-register them in the database with their public keys
    from database import SessionLocal, Device
    session = SessionLocal()
    try:
        for i in range(NUMBER_OF_DEVICES):
            device_id = f"iot_{i:05d}"
            device = VirtualDevice(device_id)
            DEVICES_MAP[device_id] = device
            
            # Pre-register in database to close the TOFU vulnerability window
            existing = session.query(Device).filter(Device.device_id == device_id).first()
            if not existing:
                new_dev = Device(
                    device_id=device_id,
                    device_name=f"Device-{device_id}",
                    cpu_usage=8.0,
                    memory_usage=128.0,
                    battery_level=100.0,
                    selected_kem="ML-KEM-512",
                    selected_signature="ML-DSA-44",
                    status="ONLINE",
                    last_seen=datetime.utcnow(),
                    sig_public_key_ml_dsa_44=device.sig_keys.get("ML-DSA-44", {}).get("public_key"),
                    sig_public_key_fn_dsa_512=device.sig_keys.get("FN-DSA-512", {}).get("public_key")
                )
                session.add(new_dev)
            else:
                # Ensure existing records have correct keys mapped
                existing.sig_public_key_ml_dsa_44 = device.sig_keys.get("ML-DSA-44", {}).get("public_key")
                existing.sig_public_key_fn_dsa_512 = device.sig_keys.get("FN-DSA-512", {}).get("public_key")
        session.commit()
        logger.info(f"Pre-registered {NUMBER_OF_DEVICES} devices with public signature keys in DB.")
    except Exception as e:
        logger.error(f"Failed to pre-register simulation devices: {e}")
        session.rollback()
    finally:
        session.close()
        
    # Start tasks
    for device in DEVICES_MAP.values():
        task = asyncio.create_task(device_loop(device, mqtt_client))
        ACTIVE_TASKS.append(task)
        
    logger.info(f"Started simulation background tasks for {NUMBER_OF_DEVICES} devices.")

async def shutdown():
    """Cancel all active tasks"""
    logger.info("Stopping simulator tasks...")
    for task in ACTIVE_TASKS:
        task.cancel()
    await asyncio.gather(*ACTIVE_TASKS, return_exceptions=True)
    ACTIVE_TASKS.clear()
    DEVICES_MAP.clear()
    logger.info("Simulator tasks stopped.")

async def main():
    """CLI Entry point for standalone running"""
    logger.info("Starting standalone simulation...")
    await start_simulator_background()
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
        sys.exit(0)