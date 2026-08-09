import json
import time
import random
import uuid

import paho.mqtt.client as mqtt

# ==========================================
# DEVICE CONFIG
# ==========================================

DEVICE_ID = f"iot_{uuid.uuid4().hex[:8]}"

MQTT_BROKER = "localhost"
MQTT_PORT = 1883

TOPIC = "iot/data"

# ==========================================
# MQTT CLIENT
# ==========================================

client = mqtt.Client()

# ==========================================
# CONNECT
# ==========================================

try:

    client.connect(
        MQTT_BROKER,
        MQTT_PORT,
        60
    )

    print(
        f"Connected MQTT: {DEVICE_ID}"
    )

except Exception as e:

    print(
        f"MQTT Error: {e}"
    )

    exit()

# ==========================================
# GENERATE TELEMETRY
# ==========================================

def generate_data():

    return {

        "device_id":
            DEVICE_ID,

        "temperature":
            round(
                random.uniform(
                    20,
                    40
                ),
                2
            ),

        "humidity":
            round(
                random.uniform(
                    30,
                    90
                ),
                2
            ),

        "battery":
            round(
                random.uniform(
                    40,
                    100
                ),
                2
            ),

        "cpu_usage":
            round(
                random.uniform(
                    5,
                    90
                ),
                2
            ),

        "memory_usage":
            round(
                random.uniform(
                    100,
                    1024
                ),
                2
            ),

        "status":
            "ONLINE"
    }

# ==========================================
# SEND LOOP
# ==========================================

def start():

    print(
        f"Starting Device: {DEVICE_ID}"
    )

    while True:

        payload = generate_data()

        client.publish(
            TOPIC,
            json.dumps(payload)
        )

        print(
            f"Sent -> {payload}"
        )

        time.sleep(2)

# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    start()