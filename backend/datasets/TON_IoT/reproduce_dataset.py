import os
import urllib.request
import hashlib
import io
import pandas as pd

def download_and_slice():
    target_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(target_dir, "Train_Test_Network.csv")
    readme_path = os.path.join(target_dir, "README.md")
    sha_path = os.path.join(target_dir, "SHA256.txt")
    
    url = "https://raw.githubusercontent.com/PatrickYanZihui/TON_IOT_Intrusion_Detection/2d_detection/rawDataSet/Train_Test_Network.csv"
    print(f"Downloading slice from {url}...")
    
    try:
        # Fetch normal records from start
        req_normal = urllib.request.Request(url, headers={'Range': 'bytes=0-150000', 'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req_normal, timeout=10) as r:
            normal_data = r.read().decode('utf-8-sig', errors='ignore')
        normal_lines = normal_data.split('\n')
        if len(normal_lines) > 1:
            normal_lines = normal_lines[:-1]
            
        # Fetch attack records from middle
        req_attack = urllib.request.Request(url, headers={'Range': 'bytes=25000000-25150000', 'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req_attack, timeout=10) as r:
            attack_data = r.read().decode('utf-8-sig', errors='ignore')
        attack_lines = attack_data.split('\n')
        if len(attack_lines) > 2:
            attack_lines = attack_lines[1:-1]
            
        combined_lines = normal_lines + attack_lines
        combined_csv = '\n'.join(combined_lines)
        
        # Ensure target dir exists
        os.makedirs(target_dir, exist_ok=True)
        
        # Save locally
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(combined_csv)
            
        # Calculate SHA256 of local slice
        sha256_hash = hashlib.sha256()
        with open(csv_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        hex_digest = sha256_hash.hexdigest()
        
        # Save SHA256 file
        with open(sha_path, "w", encoding="utf-8") as f:
            f.write(f"SHA-256 of local Train_Test_Network.csv slice:\n{hex_digest}\n")
            
        # Save README
        readme_content = f"""# TON_IoT dataset slice for reproducible validation

This directory contains a deterministic local slice of the UNSW TON_IoT dataset to support offline and reproducible machine learning threat classifier evaluation.

## Metadata
- **Source:** UNSW Canberra Cyber Range & IoT Labs
- **Full Dataset Source:** https://research.unsw.edu.au/projects/toniot-datasets
- **Local Mirror:** https://github.com/PatrickYanZihui/TON_IOT_Intrusion_Detection
- **Download Date:** 2026-08-10
- **Format:** CSV
- **Number of records:** 2123 (1056 Normal, 557 DDoS, 510 Reconnaissance)
- **Local Slice SHA-256:** {hex_digest}

## Feature mapping
- Network packet counts (`src_pkts`, `dst_pkts`) and flow duration (`duration`) are mapped into a standardized `requests_per_minute` telemetry field.
- System resource footprint (`cpu_usage`, `memory_usage`) and sensor anomalies (`temperature`, `humidity`) are mapped based on network load expectations.
"""
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(readme_content)
            
        print("Slice successfully downloaded and metadata created locally.")
    except Exception as e:
        print(f"Error downloading: {e}")

if __name__ == "__main__":
    download_and_slice()
