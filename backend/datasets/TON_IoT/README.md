# TON_IoT dataset slice for reproducible validation

This directory contains a deterministic local slice of the UNSW TON_IoT dataset to support offline and reproducible machine learning threat classifier evaluation.

## Metadata
- **Source:** UNSW Canberra Cyber Range & IoT Labs
- **Full Dataset Source:** https://research.unsw.edu.au/projects/toniot-datasets
- **Local Mirror:** https://github.com/PatrickYanZihui/TON_IOT_Intrusion_Detection
- **Download Date:** 2026-08-10
- **Format:** CSV
- **Number of records:** 2123 (1056 Normal, 557 DDoS, 510 Reconnaissance)
- **Local Slice SHA-256:** c7efd61833f838d39bd04ad4bc678edc3d223af97268a36b558b774f9054623b

## Feature mapping
- Network packet counts (`src_pkts`, `dst_pkts`) and flow duration (`duration`) are mapped into a standardized `requests_per_minute` telemetry field.
- System resource footprint (`cpu_usage`, `memory_usage`) and sensor anomalies (`temperature`, `humidity`) are mapped based on network load expectations.
