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
    print(f"Downloading full mirror dataset (approx. 46MB) from: {url}...")
    
    try:
        # Download the file fully into memory
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
            
        print(f"Download complete. Loaded {len(data)} bytes. Parsing CSV...")
        df_full = pd.read_csv(io.BytesIO(data), low_memory=False)
        print(f"Total raw records loaded: {len(df_full)}")
        
        # Standardize attack type labels
        df_full["type"] = df_full["type"].str.strip().str.lower().fillna("normal")
        
        # Deterministically sample from classes present to construct the 3-class slice:
        # Normal, DDoS (including DDoS and DoS), and Reconnaissance (scanning)
        df_normal = df_full[df_full["type"] == "normal"]
        df_ddos = df_full[df_full["type"].isin(["ddos", "dos"])]
        df_recon = df_full[df_full["type"] == "scanning"]
        
        print(f"Available records - Normal: {len(df_normal)}, DDoS/DoS: {len(df_ddos)}, Scanning: {len(df_recon)}")
        
        # Sample deterministically with fixed random state
        df_normal_sampled = df_normal.sample(n=1000, random_state=42)
        df_ddos_sampled = df_ddos.sample(n=500, random_state=42)
        df_recon_sampled = df_recon.sample(n=500, random_state=42)
        
        # Combine
        df_sliced = pd.concat([df_normal_sampled, df_ddos_sampled, df_recon_sampled]).reset_index(drop=True)
        
        # Ensure target dir exists
        os.makedirs(target_dir, exist_ok=True)
        
        # Save locally
        df_sliced.to_csv(csv_path, index=False)
        print(f"Deterministic slice containing {len(df_sliced)} records saved to: {csv_path}")
        
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
- **Number of records:** {len(df_sliced)} ({len(df_normal_sampled)} Normal, {len(df_ddos_sampled)} DDoS/DoS, {len(df_recon_sampled)} Reconnaissance)
- **Local Slice SHA-256:** {hex_digest}

## Feature mapping
- Network packet counts (`src_pkts`, `dst_pkts`) and flow duration (`duration`) are mapped into a standardized `requests_per_minute` telemetry field.
- System resource footprint (`cpu_usage`, `memory_usage`) and sensor anomalies (`temperature`, `humidity`) are mapped based on network load expectations.
"""
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(readme_content)
            
        print(f"Metadata and README generated successfully. SHA-256: {hex_digest}")
    except Exception as e:
        print(f"Error downloading: {e}")

if __name__ == "__main__":
    download_and_slice()
