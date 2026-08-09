import random
import asyncio
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from database import (
    get_db,
    init_db,
    SessionLocal,
    Device,
    ThreatLog,
    BenchmarkResult,
    engine
)
from sqlalchemy import func, text

def update_offline_devices(db: Session):
    import simulator.device_manager as dm
    timeout_secs = max(30, dm.PUBLISH_INTERVAL * 3)
    cutoff = datetime.utcnow() - timedelta(seconds=timeout_secs)
    offline_devices = (
        db.query(Device)
        .filter(Device.status == "ONLINE")
        .filter(Device.last_seen < cutoff)
        .all()
    )
    if offline_devices:
        for dev in offline_devices:
            dev.status = "OFFLINE"
        db.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    
    # Enable WAL mode on SQLite to prevent lock contentions
    try:
        if "sqlite" in str(engine.url):
            with engine.begin() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL;"))
                print("SQLite WAL mode enabled.")
    except Exception as e:
        print(f"Error setting WAL mode: {e}")
        
    print("QuantumShield API Started")
    # Start the real simulator tasks
    from simulator.device_manager import start_simulator_background, shutdown as shutdown_simulator
    from mqtt_bridge import log_event
    
    log_event("SOC", "INF", "SOC Security Operations Center online.")
    sim_task = asyncio.create_task(start_simulator_background())
    
    yield
    # Cleanup
    await shutdown_simulator()
    sim_task.cancel()

app = FastAPI(
    title="QuantumShield-IoT",
    version="1.0.0",
    lifespan=lifespan
)
app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# --------------------------------------------------
# ROOT
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "project": "QuantumShield-IoT",
        "status": "running"
    }


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# --------------------------------------------------
# REGISTER DEVICE
# --------------------------------------------------

@app.post("/devices/register")
def register_device(
    device_id: str,
    device_name: str,
    db: Session = Depends(get_db)
):

    existing = (
        db.query(Device)
        .filter(Device.device_id == device_id)
        .first()
    )

    if existing:

        return {
            "message": "Device already exists"
        }

    device = Device(
        device_id=device_id,
        device_name=device_name,
        cpu_usage=8.0,
        memory_usage=128.0,
        battery_level=100.0,
        selected_algorithm="Kyber512",
        status="ONLINE",
        last_seen=datetime.utcnow()
    )

    db.add(device)
    db.commit()
    db.refresh(device)

    # Dynamically inject into active simulator tasks
    try:
        import simulator.device_manager as dm
        from simulator.device_manager import VirtualDevice, device_loop, MQTTClient
        if dm.DEVICES_MAP is not None and device_id not in dm.DEVICES_MAP:
            client = MQTTClient()
            client.connect()
            virt_dev = VirtualDevice(device_id)
            virt_dev.battery = 100.0
            virt_dev.cpu_usage = 8.0
            virt_dev.memory_usage = 128.0
            virt_dev.requests_per_minute = 10.0
            dm.DEVICES_MAP[device_id] = virt_dev
            task = asyncio.create_task(device_loop(virt_dev, client))
            dm.ACTIVE_TASKS.append(task)
            
            from mqtt_bridge import log_event
            log_event("SOC", "INF", f"Dynamically added virtual device '{device_id}' to active simulation.")
    except Exception as e:
        print(f"Failed to dynamically add device to simulator: {e}")

    return {
        "message": "Device Registered",
        "id": device.id
    }


# --------------------------------------------------
# GET DEVICES
# --------------------------------------------------

@app.get("/devices")
def get_devices(
    db: Session = Depends(get_db)
):
    update_offline_devices(db)
    devices = db.query(Device).all()

    return devices


# --------------------------------------------------
# GET THREATS
# --------------------------------------------------

@app.get("/threats")
def get_threats(
    db: Session = Depends(get_db)
):

    threats = db.query(ThreatLog).all()

    return threats

@app.get("/stats")
def get_stats(
    db: Session = Depends(get_db)
):
    update_offline_devices(db)
    total_devices = (
        db.query(Device)
        .count()
    )

    active_devices = (
        db.query(Device)
        .filter(
            Device.status == "ONLINE"
        )
        .count()
    )

    total_threats = (
        db.query(ThreatLog)
        .count()
    )

    blocked_threats = (
        db.query(ThreatLog)
        .filter(ThreatLog.blocked == True)
        .count()
    )

    avg_cpu = (
        db.query(
            func.avg(
                Device.cpu_usage
            )
        ).scalar()
        or 0
    )

    avg_memory = (
        db.query(
            func.avg(
                Device.memory_usage
            )
        ).scalar()
        or 0
    )

    avg_battery = (
        db.query(
            func.avg(
                Device.battery_level
            )
        ).scalar()
        or 0
    )

    pqc_algorithms = (
        db.query(
            Device.selected_algorithm
        )
        .distinct()
        .count()
    )

    # Average Benchmark Metrics
    avg_keygen_ms = db.query(func.avg(BenchmarkResult.keygen_time_ms)).scalar() or 0
    avg_encapsulation_ms = db.query(func.avg(BenchmarkResult.encapsulation_time_ms)).scalar() or 0
    avg_decapsulation_ms = db.query(func.avg(BenchmarkResult.decapsulation_time_ms)).scalar() or 0
    avg_pqc_mem_mb = db.query(func.avg(BenchmarkResult.memory_usage_mb)).scalar() or 0

    threat_rate = 0
    block_rate = 100.0

    if total_devices > 0:
        threat_rate = round(
            (
                total_threats
                /
                total_devices
            ),
            2
        )

    if total_threats > 0:
        block_rate = round(
            (
                blocked_threats
                /
                total_threats
            ) * 100,
            2
        )

    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "total_threats": total_threats,
        "blocked_threats": blocked_threats,
        "block_rate": block_rate,
        "threat_rate": threat_rate,
        "pqc_algorithms": pqc_algorithms,
        "avg_cpu": round(float(avg_cpu), 2),
        "avg_memory": round(float(avg_memory), 2),
        "avg_battery": round(float(avg_battery), 2),
        "avg_keygen_ms": round(float(avg_keygen_ms), 4),
        "avg_encapsulation_ms": round(float(avg_encapsulation_ms), 4),
        "avg_decapsulation_ms": round(float(avg_decapsulation_ms), 4),
        "avg_pqc_mem_mb": round(float(avg_pqc_mem_mb), 2)
    }

@app.get("/device-summary")
def device_summary(
    db: Session = Depends(get_db)
):
    update_offline_devices(db)
    total = (
        db.query(Device)
        .count()
    )

    online = (
        db.query(Device)
        .filter(
            Device.status == "ONLINE"
        )
        .count()
    )

    offline = (
        db.query(Device)
        .filter(
            Device.status == "OFFLINE"
        )
        .count()
    )

    avg_battery = (
        db.query(
            func.avg(
                Device.battery_level
            )
        ).scalar()
        or 0
    )

    return {

        "total_devices":
            total,

        "online_devices":
            online,

        "offline_devices":
            offline,

        "avg_battery":
            round(
                float(avg_battery),
                2
            )
    }

@app.get("/threat-summary")
def threat_summary(
    db: Session = Depends(get_db)
):

    high = (
        db.query(ThreatLog)
        .filter(
            ThreatLog.severity
            == "HIGH"
        )
        .count()
    )

    medium = (
        db.query(ThreatLog)
        .filter(
            ThreatLog.severity
            == "MEDIUM"
        )
        .count()
    )

    low = (
        db.query(ThreatLog)
        .filter(
            ThreatLog.severity
            == "LOW"
        )
        .count()
    )

    total = (
        db.query(ThreatLog)
        .count()
    )

    return {

        "total":
            total,

        "high":
            high,

        "medium":
            medium,

        "low":
            low
    }

@app.get("/top-attacked-devices")
def top_attacked_devices(
    db: Session = Depends(get_db)
):

    results = (

        db.query(
            ThreatLog.device_id,
            func.count(
                ThreatLog.id
            ).label("threats")
        )

        .group_by(
            ThreatLog.device_id
        )

        .order_by(
            func.count(
                ThreatLog.id
            ).desc()
        )

        .limit(10)

        .all()
    )

    return [

        {
            "device_id":
                r.device_id,

            "threats":
                r.threats
        }

        for r in results
    ]

@app.get("/threat-timeline")
def threat_timeline(
    db: Session = Depends(get_db)
):
    if "sqlite" in str(db.bind.url):
        results = (
            db.query(
                func.strftime("%Y-%m-%d %H:%M:00", ThreatLog.timestamp).label("time"),
                func.count(ThreatLog.id).label("count")
            )
            .group_by("time")
            .order_by("time")
            .all()
        )
    else:
        results = (
            db.query(
                func.date_trunc(
                    "minute",
                    ThreatLog.timestamp
                ).label(
                    "time"
                ),
                func.count(
                    ThreatLog.id
                ).label(
                    "count"
                )
            )
            .group_by("time")
            .order_by("time")
            .all()
        )

    return [

        {
            "time":
                str(r.time),

            "count":
                r.count
        }

        for r in results
    ]
# --------------------------------------------------
# GET BENCHMARKS
# --------------------------------------------------

@app.get("/benchmarks")
def get_benchmarks(
    db: Session = Depends(get_db)
):

    benchmarks = (
        db.query(BenchmarkResult)
        .all()
    )

    return benchmarks

@app.get("/pqc-distribution")
def pqc_distribution(
    db: Session = Depends(get_db)
):

    results = (

        db.query(
            Device.selected_algorithm,
            func.count(Device.id)
        )

        .group_by(
            Device.selected_algorithm
        )

        .all()

    )

    return [

        {
            "algorithm": r[0],
            "count": r[1]
        }

        for r in results
    ]

# --------------------------------------------------
# SIMULATOR & LOGS API
# --------------------------------------------------

@app.get("/logs")
def get_logs():
    from mqtt_bridge import SYSTEM_LOGS
    return SYSTEM_LOGS

@app.get("/simulator/config")
def get_simulator_config():
    import simulator.device_manager as dm
    return {
        "publish_interval": dm.PUBLISH_INTERVAL,
        "attack_probability": dm.ATTACK_PROBABILITY,
        "active_devices": len(dm.DEVICES_MAP)
    }

@app.post("/simulator/config")
def update_simulator_config(publish_interval: int = None, attack_probability: float = None):
    import simulator.device_manager as dm
    from mqtt_bridge import log_event
    if publish_interval is not None:
        dm.PUBLISH_INTERVAL = max(1, min(60, publish_interval))
    if attack_probability is not None:
        dm.ATTACK_PROBABILITY = max(0.0, min(1.0, attack_probability))
    
    log_event("SOC", "INF", f"Simulator config updated: publish_interval={dm.PUBLISH_INTERVAL}s, attack_probability={dm.ATTACK_PROBABILITY*100:.2f}%")
    return {
        "status": "success",
        "publish_interval": dm.PUBLISH_INTERVAL,
        "attack_probability": dm.ATTACK_PROBABILITY
    }

@app.post("/simulator/trigger-attack")
def trigger_attack(attack_type: str, device_id: str = None):
    import simulator.device_manager as dm
    from mqtt_bridge import log_event
    
    if not dm.DEVICES_MAP:
        return {"status": "error", "message": "Simulator is not running."}
        
    target_device = None
    if device_id:
        target_device = dm.DEVICES_MAP.get(device_id)
    else:
        # Pick a random normal device
        normal_devices = [d for d in dm.DEVICES_MAP.values() if d.state == "NORMAL" and d.battery > 10.0]
        if normal_devices:
            target_device = random.choice(normal_devices)
            
    if not target_device:
        return {"status": "error", "message": "No eligible device found."}
        
    success = target_device.trigger_attack(attack_type)
    if success:
        log_event("SOC", "WRN", f"Interactive attack injection: triggered {attack_type} on {target_device.device_id}")
        return {
            "status": "success",
            "device_id": target_device.device_id,
            "attack_type": attack_type
        }
    else:
        return {"status": "error", "message": f"Device {target_device.device_id} is already in state {target_device.state}"}

@app.post("/simulator/reset")
def reset_simulator(db: Session = Depends(get_db)):
    import simulator.device_manager as dm
    from mqtt_bridge import log_event, SYSTEM_LOGS
    
    # Reset all devices in memory
    for device in dm.DEVICES_MAP.values():
        device.reset()
        
    # Reset all devices in database
    devices = db.query(Device).all()
    for dev in devices:
        dev.status = "ONLINE"
        dev.cpu_usage = 8.0
        dev.memory_usage = 128.0
        dev.battery_level = 100.0
        dev.selected_algorithm = "Kyber512"
        dev.last_seen = datetime.utcnow()
    db.commit()
    
    # Clear threat logs
    db.query(ThreatLog).delete()
    db.commit()
    
    # Clear logs and trigger reset event
    SYSTEM_LOGS.clear()
    log_event("SOC", "INF", "SOC simulation reset: cleared threat logs, unblocked devices, restored all battery levels.")
    
    return {"status": "success", "message": "Simulator fleet and threat database reset."}