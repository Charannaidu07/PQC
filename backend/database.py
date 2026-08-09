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

DB_USER = "postgres"
DB_PASSWORD = "postgres"
DB_HOST = "127.0.0.1"
DB_PORT = "5432"
DB_NAME = "quantumshield"

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
        default=datetime.utcnow
    )

# =====================================================
# THREAT LOG TABLE
# =====================================================

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)

    device_id = Column(
        String(100),
        nullable=False
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
        default="Normal"
    )

    confidence = Column(
        Float,
        default=0.0
    )

    severity = Column(
        String(50),
        default="LOW"
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
        default=datetime.utcnow
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

def run_migrations():
    """Runs schema migrations on the database to add missing fields/columns."""
    from sqlalchemy import text
    try:
        with engine.begin() as conn:
            # Query first row to see if columns are present
            res = conn.execute(text("SELECT * FROM devices LIMIT 1"))
            columns = res.keys()
            
            # Check and add sig_public_key_ml_dsa_44
            if "sig_public_key_ml_dsa_44" not in columns:
                print("Adding column sig_public_key_ml_dsa_44 to table devices...")
                conn.execute(text("ALTER TABLE devices ADD COLUMN sig_public_key_ml_dsa_44 VARCHAR(2500)"))
                if "sig_public_key_dilithium2" in columns:
                    conn.execute(text("UPDATE devices SET sig_public_key_ml_dsa_44 = sig_public_key_dilithium2"))
                
            # Check and add sig_public_key_fn_dsa_512
            if "sig_public_key_fn_dsa_512" not in columns:
                print("Adding column sig_public_key_fn_dsa_512 to table devices...")
                conn.execute(text("ALTER TABLE devices ADD COLUMN sig_public_key_fn_dsa_512 VARCHAR(2500)"))
                if "sig_public_key_falcon512" in columns:
                    conn.execute(text("UPDATE devices SET sig_public_key_fn_dsa_512 = sig_public_key_falcon512"))
                
            # Check and add last_sequence
            if "last_sequence" not in columns:
                print("Adding column last_sequence to table devices...")
                conn.execute(text("ALTER TABLE devices ADD COLUMN last_sequence INTEGER DEFAULT 0"))
                
    except Exception as e:
        print(f"Database migration error: {e}")

def run_benchmark_migrations():
    """Runs schema migrations to add statistical columns to benchmark_results table."""
    from sqlalchemy import text
    try:
        with engine.begin() as conn:
            res = conn.execute(text("SELECT * FROM benchmark_results LIMIT 1"))
            columns = res.keys()
            
            prefixes = ["keygen", "encap", "decap", "sign", "verify"]
            suffixes = ["mean_ms", "median_ms", "std_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"]
            
            for prefix in prefixes:
                for suffix in suffixes:
                    col_name = f"{prefix}_{suffix}"
                    if col_name not in columns:
                        print(f"Adding column {col_name} to table benchmark_results...")
                        conn.execute(text(f"ALTER TABLE benchmark_results ADD COLUMN {col_name} FLOAT"))
    except Exception as e:
        print(f"Database benchmark migration error: {e}")

def run_benchmark_size_migrations():
    """Runs schema migrations to add key/ciphertext/signature size columns to benchmark_results table."""
    from sqlalchemy import text
    try:
        with engine.begin() as conn:
            res = conn.execute(text("SELECT * FROM benchmark_results LIMIT 1"))
            columns = res.keys()
            
            size_cols = [
                "pub_key_size_bytes",
                "secret_key_size_bytes",
                "ciphertext_size_bytes",
                "shared_secret_size_bytes",
                "signature_size_bytes"
            ]
            
            for col in size_cols:
                if col not in columns:
                    print(f"Adding column {col} to table benchmark_results...")
                    conn.execute(text(f"ALTER TABLE benchmark_results ADD COLUMN {col} INTEGER"))
    except Exception as e:
        print(f"Database benchmark size migration error: {e}")

def init_db():

    Base.metadata.create_all(bind=engine)
    run_migrations()
    run_benchmark_migrations()
    run_benchmark_size_migrations()

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