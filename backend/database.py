"""
database.py
------------
PostgreSQL Database Configuration and Models
QuantumShield-IoT

Tables:
1. devices
2. threat_logs
3. benchmark_results
"""

from datetime import datetime

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Boolean
)

from sqlalchemy.orm import (
    declarative_base,
    sessionmaker
)

# =====================================================
# DATABASE CONFIG
# =====================================================

import os

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "quantumshield")

from sqlalchemy import text

DATABASE_URL = (
    f"postgresql://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

# =====================================================
# ENGINE
# =====================================================

try:
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        pool_pre_ping=True
    )
    # Test connection
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
        print("Database Connected Successfully (PostgreSQL)")
except Exception as e:
    # Fail hard if PostgreSQL env variables are explicitly configured to prevent silent fallback
    if os.getenv("DB_HOST") or os.getenv("DB_USER"):
        import sys
        print("CRITICAL DATABASE ERROR: PostgreSQL connection failed as configured. Failing hard to prevent silent fallback.")
        print(f"Error details: {e}")
        sys.exit(1)
        
    print("PostgreSQL Database Connection Failed, falling back to SQLite.")
    print(f"Error: {e}")
    import os
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    sqlite_db_path = os.path.join(backend_dir, "quantumshield.db")
    DATABASE_URL = f"sqlite:///{sqlite_db_path.replace('\\', '/')}"
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
    )
    print(f"Database Connected Successfully (SQLite) at: {sqlite_db_path}")

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# =====================================================
# DEVICE TABLE
# =====================================================

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)

    device_id = Column(
        String(100),
        unique=True,
        nullable=False
    )

    device_name = Column(
        String(255),
        nullable=False
    )

    status = Column(
        String(50),
        default="ONLINE"
    )

    cpu_usage = Column(
        Float,
        default=0.0
    )

    memory_usage = Column(
        Float,
        default=0.0
    )

    battery_level = Column(
        Float,
        default=100.0
    )

    selected_kem = Column(
        String(100),
        default="ML-KEM-512"
    )

    selected_signature = Column(
        String(100),
        default="ML-DSA-44"
    )

    sig_public_key_ml_dsa_44 = Column(
        String(2500),
        nullable=True
    )

    sig_public_key_fn_dsa_512 = Column(
        String(2500),
        nullable=True
    )

    last_sequence = Column(
        Integer,
        default=0
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    last_seen = Column(
        DateTime,
        default=datetime.utcnow,
        index=True
    )

# =====================================================
# THREAT LOG TABLE
# =====================================================

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)

    device_id = Column(
        String(100),
        nullable=False,
        index=True
    )

    threat_type = Column(
        String(100),
        nullable=False
    )

    ground_truth_type = Column(
        String(100),
        default="Normal"
    )

    predicted_type = Column(
        String(100),
        default="Normal",
        index=True
    )

    confidence = Column(
        Float,
        default=0.0
    )

    severity = Column(
        String(50),
        default="LOW",
        index=True
    )

    temperature = Column(
        Float,
        default=0.0
    )

    humidity = Column(
        Float,
        default=0.0
    )

    cpu_usage = Column(
        Float,
        default=0.0
    )

    memory_usage = Column(
        Float,
        default=0.0
    )

    requests_per_minute = Column(
        Float,
        default=0.0
    )

    blocked = Column(
        Boolean,
        default=False
    )

    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        index=True
    )
# =====================================================
# BENCHMARK RESULTS TABLE
# =====================================================

class BenchmarkResult(Base):
    __tablename__ = "benchmark_results"

    id = Column(Integer, primary_key=True, index=True)

    algorithm = Column(
        String(100),
        nullable=False
    )

    keygen_time_ms = Column(
        Float,
        default=0.0
    )

    encapsulation_time_ms = Column(
        Float,
        default=0.0
    )

    decapsulation_time_ms = Column(
        Float,
        default=0.0
    )

    signature_time_ms = Column(
        Float,
        default=0.0
    )

    verify_time_ms = Column(
        Float,
        default=0.0
    )

    # Statistical keygen columns
    keygen_mean_ms = Column(Float, default=0.0)
    keygen_median_ms = Column(Float, default=0.0)
    keygen_std_ms = Column(Float, default=0.0)
    keygen_p95_ms = Column(Float, default=0.0)
    keygen_p99_ms = Column(Float, default=0.0)
    keygen_min_ms = Column(Float, default=0.0)
    keygen_max_ms = Column(Float, default=0.0)

    # Statistical encapsulation columns
    encap_mean_ms = Column(Float, default=0.0)
    encap_median_ms = Column(Float, default=0.0)
    encap_std_ms = Column(Float, default=0.0)
    encap_p95_ms = Column(Float, default=0.0)
    encap_p99_ms = Column(Float, default=0.0)
    encap_min_ms = Column(Float, default=0.0)
    encap_max_ms = Column(Float, default=0.0)

    # Statistical decapsulation columns
    decap_mean_ms = Column(Float, default=0.0)
    decap_median_ms = Column(Float, default=0.0)
    decap_std_ms = Column(Float, default=0.0)
    decap_p95_ms = Column(Float, default=0.0)
    decap_p99_ms = Column(Float, default=0.0)
    decap_min_ms = Column(Float, default=0.0)
    decap_max_ms = Column(Float, default=0.0)

    # Statistical signing columns
    sign_mean_ms = Column(Float, default=0.0)
    sign_median_ms = Column(Float, default=0.0)
    sign_std_ms = Column(Float, default=0.0)
    sign_p95_ms = Column(Float, default=0.0)
    sign_p99_ms = Column(Float, default=0.0)
    sign_min_ms = Column(Float, default=0.0)
    sign_max_ms = Column(Float, default=0.0)

    # Statistical verification columns
    verify_mean_ms = Column(Float, default=0.0)
    verify_median_ms = Column(Float, default=0.0)
    verify_std_ms = Column(Float, default=0.0)
    verify_p95_ms = Column(Float, default=0.0)
    verify_p99_ms = Column(Float, default=0.0)
    verify_min_ms = Column(Float, default=0.0)
    verify_max_ms = Column(Float, default=0.0)

    memory_usage_mb = Column(
        Float,
        default=0.0
    )

    cpu_usage_percent = Column(
        Float,
        default=0.0
    )

    pub_key_size_bytes = Column(Integer, default=0)
    secret_key_size_bytes = Column(Integer, default=0)
    ciphertext_size_bytes = Column(Integer, default=0)
    shared_secret_size_bytes = Column(Integer, default=0)
    signature_size_bytes = Column(Integer, default=0)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )

# =====================================================
# DATABASE FUNCTIONS
# =====================================================

def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()

# =====================================================
# CREATE TABLES
# =====================================================

def init_db():
    import os
    from alembic.config import Config
    from alembic import command

    # Issue 37: Rely strictly on Alembic migrations as the sole authoritative schema manager
    # Removed Base.metadata.create_all(bind=engine)
    
    # Run Alembic migrations programmatically to apply updates & clean legacy columns
    try:
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        ini_path = os.path.join(backend_dir, "alembic.ini")
        alembic_cfg = Config(ini_path)
        alembic_cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
        command.upgrade(alembic_cfg, "head")
        print("Database migrations applied successfully via Alembic.")
    except Exception as e:
        print(f"Failed to run Alembic database migrations: {e}")

    print("QuantumShield Database Initialized")

# =====================================================
# TEST
# =====================================================

if __name__ == "__main__":
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            print("Database Connected Successfully")
    except Exception as e:
        print("Database Connection Failed")
        print(e)

    init_db()

    print("Tables Created Successfully")