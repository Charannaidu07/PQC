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

    selected_algorithm = Column(
        String(100),
        default="Kyber512"
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

    memory_usage_mb = Column(
        Float,
        default=0.0
    )

    cpu_usage_percent = Column(
        Float,
        default=0.0
    )

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

    Base.metadata.create_all(bind=engine)

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