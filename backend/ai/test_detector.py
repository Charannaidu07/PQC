from threat_detector import detect_threat

payload = {

    "device_id": "iot_attack",

    "temperature": 95,

    "humidity": 5,

    "cpu_usage": 99,

    "memory_usage": 2500,

    "requests_per_minute": 3000
}

result = detect_threat(payload)

print(result)