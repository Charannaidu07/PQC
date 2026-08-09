from threat_detector import detect_threat

# Test Normal
payload_normal = {
    "device_id": "device_normal",
    "temperature": 24,
    "humidity": 45,
    "cpu_usage": 12,
    "memory_usage": 180,
    "requests_per_minute": 15
}

# Test DDoS
payload_ddos = {
    "device_id": "device_ddos",
    "temperature": 32,
    "humidity": 55,
    "cpu_usage": 85,
    "memory_usage": 950,
    "requests_per_minute": 2200
}

# Test Cryptojacking
payload_crypto = {
    "device_id": "device_crypto",
    "temperature": 48,
    "humidity": 60,
    "cpu_usage": 98,
    "memory_usage": 1400,
    "requests_per_minute": 20
}

# Test Thermal Tampering
payload_thermal = {
    "device_id": "device_thermal",
    "temperature": 95,
    "humidity": 10,
    "cpu_usage": 22,
    "memory_usage": 150,
    "requests_per_minute": 12
}

# Test Reconnaissance
payload_recon = {
    "device_id": "device_recon",
    "temperature": 28,
    "humidity": 50,
    "cpu_usage": 32,
    "memory_usage": 280,
    "requests_per_minute": 280
}

print("1. Testing Normal Payload:")
print("Result:", detect_threat(payload_normal))

print("\n2. Testing DDoS Payload:")
print("Result:", detect_threat(payload_ddos))

print("\n3. Testing Cryptojacking Payload:")
print("Result:", detect_threat(payload_crypto))

print("\n4. Testing Thermal Tampering Payload:")
print("Result:", detect_threat(payload_thermal))

print("\n5. Testing Reconnaissance Payload:")
print("Result:", detect_threat(payload_recon))