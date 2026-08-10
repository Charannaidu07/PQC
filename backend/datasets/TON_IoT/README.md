# TON_IoT dataset slice for reproducible validation

This directory contains a deterministic local slice of the UNSW TON_IoT dataset to support offline and reproducible machine learning threat classifier evaluation.

## Metadata
- **Source:** UNSW Canberra Cyber Range & IoT Labs
- **Full Dataset Source:** https://research.unsw.edu.au/projects/toniot-datasets
- **Local Mirror:** https://github.com/PatrickYanZihui/TON_IOT_Intrusion_Detection
- **Download Date:** 2026-08-10
- **Format:** CSV
- **Number of records:** 2000 (1000 Normal, 500 DDoS/DoS, 500 Reconnaissance)
- **Local Slice SHA-256:** e78d9aa7f2851e3830c6c7e0479a5a4bb1076ea209f880b37b8722db07a1f599

## Feature mapping
- Network packet counts (`src_pkts`, `dst_pkts`) and flow duration (`duration`) are mapped into a standardized `requests_per_minute` telemetry field.
- System resource footprint (`cpu_usage`, `memory_usage`) and sensor anomalies (`temperature`, `humidity`) are mapped based on network load expectations.
