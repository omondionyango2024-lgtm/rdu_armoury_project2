# =========================================================================
# SYSTEM DATA SCHEMATIC ARCHITECTURE LAYER (3NF NORMALIZATION)
# COMPLIANCE: EXPLICIT DATATYPE DECLARATIONS FOR MODERN PYCHARM ENGINE
# DESIGN PRINCIPLE: CASCADING DELETE PROTECTIONS FOR AUDIT TRACKING
# CORRECTION APPLIED: REVERTED ALL PROPERTIES TO STANDARD 'password_hash'
# =========================================================================

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

# Instantiate the shared database mapping context engine
db = SQLAlchemy()


class User(db.Model):
    """Stores secure identity records, police ranks, and access permissions."""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(100), nullable=False)
    rank = db.Column(db.String(50), nullable=False)
    role_permissions = db.Column(db.String(30), nullable=False)  # Admin, Armourer, Field_Officer
    password_hash = db.Column(db.String(255), nullable=False)     # CORRECTED TO STANDARD HASH
    account_status = db.Column(db.String(20), default='Active', nullable=False)


class FirearmInventory(db.Model):
    """Maintains individual lifespans and ready-states for military ordnance."""

    __tablename__ = 'firearms_inventory'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    serial_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    make_model = db.Column(db.String(100), nullable=False)
    weapon_type = db.Column(db.String(50), nullable=False)
    caliber = db.Column(db.String(30), nullable=False)
    operational_status = db.Column(db.String(30), default='Available', nullable=False)
    cumulative_rounds_fired = db.Column(db.Integer, default=0, nullable=False)
    date_procured = db.Column(db.Date, nullable=False)


class DeploymentLog(db.Model):
    """Monitors atomic transactions joining field units to discrete assets."""

    __tablename__ = 'deployment_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    officer_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='RESTRICT'),
        nullable=False
    )
    armourer_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='RESTRICT'),
        nullable=False
    )
    firearm_id = db.Column(
        db.Integer,
        db.ForeignKey('firearms_inventory.id', ondelete='RESTRICT'), nullable=True
    )
    purpose_operation = db.Column(db.String(255), nullable=False)
    checkout_timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expected_return_date = db.Column(db.Date, nullable=False)
    checkin_timestamp = db.Column(db.DateTime(timezone=True), nullable=True)
    log_status = db.Column(db.String(30), default='Active', nullable=False, index=True)