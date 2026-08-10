"""Initial migration

Revision ID: f6d76828be4d
Revises: 
Create Date: 2026-08-10 17:34:11.553266

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6d76828be4d'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    # 1. DEVICES TABLE
    if 'devices' not in tables:
        op.create_table(
            'devices',
            sa.Column('id', sa.Integer(), primary_key=True, index=True),
            sa.Column('device_id', sa.String(length=100), unique=True, nullable=False),
            sa.Column('device_name', sa.String(length=255), nullable=False),
            sa.Column('status', sa.String(length=50), server_default='ONLINE'),
            sa.Column('cpu_usage', sa.Float(), server_default='0.0'),
            sa.Column('memory_usage', sa.Float(), server_default='0.0'),
            sa.Column('battery_level', sa.Float(), server_default='100.0'),
            sa.Column('selected_kem', sa.String(length=100), server_default='ML-KEM-512'),
            sa.Column('selected_signature', sa.String(length=100), server_default='ML-DSA-44'),
            sa.Column('sig_public_key_ml_dsa_44', sa.String(length=2500), nullable=True),
            sa.Column('sig_public_key_fn_dsa_512', sa.String(length=2500), nullable=True),
            sa.Column('last_sequence', sa.Integer(), server_default='0'),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('last_seen', sa.DateTime(), nullable=True)
        )
    else:
        columns = [c['name'] for c in inspector.get_columns('devices')]
        
        # Add new columns if missing
        if 'sig_public_key_ml_dsa_44' not in columns:
            op.add_column('devices', sa.Column('sig_public_key_ml_dsa_44', sa.String(length=2500), nullable=True))
        if 'sig_public_key_fn_dsa_512' not in columns:
            op.add_column('devices', sa.Column('sig_public_key_fn_dsa_512', sa.String(length=2500), nullable=True))
        if 'last_sequence' not in columns:
            op.add_column('devices', sa.Column('last_sequence', sa.Integer(), server_default='0'))
            
        # Migrate data from legacy columns to new standard columns
        if 'sig_public_key_dilithium2' in columns:
            bind.execute(sa.text("UPDATE devices SET sig_public_key_ml_dsa_44 = sig_public_key_dilithium2 WHERE sig_public_key_ml_dsa_44 IS NULL"))
        if 'sig_public_key_falcon512' in columns:
            bind.execute(sa.text("UPDATE devices SET sig_public_key_fn_dsa_512 = sig_public_key_falcon512 WHERE sig_public_key_fn_dsa_512 IS NULL"))
            
        # Drop legacy columns cleanly
        with op.batch_alter_table('devices') as batch_op:
            if 'sig_public_key_dilithium2' in columns:
                batch_op.drop_column('sig_public_key_dilithium2')
            if 'sig_public_key_falcon512' in columns:
                batch_op.drop_column('sig_public_key_falcon512')

    # 2. THREAT LOGS TABLE
    if 'threat_logs' not in tables:
        op.create_table(
            'threat_logs',
            sa.Column('id', sa.Integer(), primary_key=True, index=True),
            sa.Column('device_id', sa.String(length=100), nullable=False),
            sa.Column('threat_type', sa.String(length=100), nullable=False),
            sa.Column('ground_truth_type', sa.String(length=100), server_default='Normal'),
            sa.Column('predicted_type', sa.String(length=100), server_default='Normal'),
            sa.Column('confidence', sa.Float(), server_default='0.0'),
            sa.Column('severity', sa.String(length=50), server_default='LOW'),
            sa.Column('temperature', sa.Float(), server_default='0.0'),
            sa.Column('humidity', sa.Float(), server_default='0.0'),
            sa.Column('cpu_usage', sa.Float(), server_default='0.0'),
            sa.Column('memory_usage', sa.Float(), server_default='0.0'),
            sa.Column('requests_per_minute', sa.Float(), server_default='0.0'),
            sa.Column('blocked', sa.Boolean(), server_default='0'),
            sa.Column('timestamp', sa.DateTime(), nullable=True)
        )
    else:
        columns = [c['name'] for c in inspector.get_columns('threat_logs')]
        if 'ground_truth_type' not in columns:
            op.add_column('threat_logs', sa.Column('ground_truth_type', sa.String(length=100), server_default='Normal'))
        if 'predicted_type' not in columns:
            op.add_column('threat_logs', sa.Column('predicted_type', sa.String(length=100), server_default='Normal'))

    # 3. BENCHMARK RESULTS TABLE
    if 'benchmark_results' not in tables:
        op.create_table(
            'benchmark_results',
            sa.Column('id', sa.Integer(), primary_key=True, index=True),
            sa.Column('algorithm', sa.String(length=100), nullable=False),
            sa.Column('keygen_time_ms', sa.Float(), server_default='0.0'),
            sa.Column('encapsulation_time_ms', sa.Float(), server_default='0.0'),
            sa.Column('decapsulation_time_ms', sa.Float(), server_default='0.0'),
            sa.Column('signature_time_ms', sa.Float(), server_default='0.0'),
            sa.Column('verify_time_ms', sa.Float(), server_default='0.0'),
            sa.Column('memory_usage_mb', sa.Float(), server_default='0.0'),
            sa.Column('cpu_usage_percent', sa.Float(), server_default='0.0'),
            sa.Column('pub_key_size_bytes', sa.Integer(), server_default='0'),
            sa.Column('secret_key_size_bytes', sa.Integer(), server_default='0'),
            sa.Column('ciphertext_size_bytes', sa.Integer(), server_default='0'),
            sa.Column('shared_secret_size_bytes', sa.Integer(), server_default='0'),
            sa.Column('signature_size_bytes', sa.Integer(), server_default='0'),
            sa.Column('timestamp', sa.DateTime(), nullable=True)
        )
        
        # Add statistical columns
        prefixes = ["keygen", "encap", "decap", "sign", "verify"]
        suffixes = ["mean_ms", "median_ms", "std_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"]
        for prefix in prefixes:
            for suffix in suffixes:
                op.add_column('benchmark_results', sa.Column(f"{prefix}_{suffix}", sa.Float(), server_default='0.0'))
    else:
        columns = [c['name'] for c in inspector.get_columns('benchmark_results')]
        
        # Check and add stats columns
        prefixes = ["keygen", "encap", "decap", "sign", "verify"]
        suffixes = ["mean_ms", "median_ms", "std_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"]
        for prefix in prefixes:
            for suffix in suffixes:
                col_name = f"{prefix}_{suffix}"
                if col_name not in columns:
                    op.add_column('benchmark_results', sa.Column(col_name, sa.Float(), server_default='0.0'))
                    
        # Check and add size columns
        size_cols = [
            "pub_key_size_bytes",
            "secret_key_size_bytes",
            "ciphertext_size_bytes",
            "shared_secret_size_bytes",
            "signature_size_bytes"
        ]
        for col in size_cols:
            if col not in columns:
                op.add_column('benchmark_results', sa.Column(col, sa.Integer(), server_default='0'))


def downgrade() -> None:
    """Downgrade schema."""
    # Restore legacy columns for fallback compatibility if downgraded
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()
    
    if 'devices' in tables:
        columns = [c['name'] for c in inspector.get_columns('devices')]
        with op.batch_alter_table('devices') as batch_op:
            if 'sig_public_key_dilithium2' not in columns:
                batch_op.add_column(sa.Column('sig_public_key_dilithium2', sa.String(length=2500), nullable=True))
            if 'sig_public_key_falcon512' not in columns:
                batch_op.add_column(sa.Column('sig_public_key_falcon512', sa.String(length=2500), nullable=True))
                
        # Copy data back
        bind.execute(sa.text("UPDATE devices SET sig_public_key_dilithium2 = sig_public_key_ml_dsa_44"))
        bind.execute(sa.text("UPDATE devices SET sig_public_key_falcon512 = sig_public_key_fn_dsa_512"))
