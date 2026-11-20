# =========================================================================
# SYSTEM APPLICATION CONTROLLER & BUSINESS LOGIC ENGINE
# COMPLIANCE: FLASK-SQLALCHEMY ACTIVE APPLICATION CONTEXT RULES
# CORRECTION APPLIED: DYNAMIC PROD/DEV DATABASE ROUTING INTERFACE
# =========================================================================

import os
import csv
import io
from datetime import datetime, timezone
from flask import Flask, request, session, redirect, url_for, flash, render_template, Response
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError
from models import db, User, FirearmInventory, DeploymentLog, AmmoTransaction
from functools import wraps

app = Flask(__name__)

# System Encryption Security Key for Client-Side Session Signatures
app.secret_key = 'RDU_APS_METADATA_SECRET_CRYPTO_KEY'

# DYNAMIC DATABASE HOST ROUTING MATRIX
# Automatically intercepts live cloud configurations while safeguarding local setups
if os.environ.get('DATABASE_URL'):
    # Render builds database URLs with 'postgres://', but SQLAlchemy 2.0 strictly requires 'postgresql://'
    database_uri = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
else:
    # Local fallback for development workstation environment
    database_uri = 'postgresql://postgres:admin@localhost:5432/rdu_aps_secure_armoury_tracking_system'

app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database extension instance with active application context
db.init_app(app)

def roles_required(*allowed_roles):
    """Restricts route access to specified clearance roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Access Denied: Please authenticate security credentials.', 'danger')
                return redirect(url_for('login_view'))
            if session.get('role') not in allowed_roles:
                flash('Security Clearance Violation: You do not have permission to access this resource.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# =========================================================================
# LIVE PRODUCTION SCHEMATIC INITIALIZER
# Forces Render to check and generate missing SQL tables on first page request
# =========================================================================
@app.before_request
def initialize_database_schema_on_startup():
    # Removes itself after running once so it never slows down your application
    app.before_request_funcs[None].remove(initialize_database_schema_on_startup)
    try:
        db.create_all()
        print("[PROD INIT] PostgreSQL database schema verified and generated.")
    except Exception as initialization_failure:
        print(f"[PROD INIT CRITICAL] Table generation crashed: {initialization_failure}")


# =========================================================================
# ROUTING LOGIC LAYER A: USER AUTHENTICATION & PORTAL PROTECTION GATEWAYS
# =========================================================================

@app.route('/')
def login_view():
    """Renders the secure gateway login form view component."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def process_login():
    """Diagnostic login controller checking actual string states."""
    service_num = request.form.get('service_number', '').strip()
    user_input_pass = request.form.get('password', '').strip()

    user = db.session.query(User).filter_by(service_number=service_num).first()

    if user:
        try:
            is_valid = check_password_hash(user.password_hash, user_input_pass)
        except Exception:
            is_valid = False

        if is_valid:
            session['user_id'] = user.id
            session['full_name'] = user.full_name
            session['role'] = user.role_permissions
            flash('Authentication successful. Access granted.', 'success')
            return redirect(url_for('dashboard'))

    flash('Security Authentication Failed. Invalid service number or pin.', 'danger')
    return redirect(url_for('login_view'))


# =========================================================================
# ROUTING LOGIC LAYER B: USER REGISTRATION & RECRUITMENT GATEWAYS
# =========================================================================

@app.route('/signup', methods=['GET', 'POST'])
def process_signup():
    """Handles secure new user provisioning and structural password hashing."""
    if request.method == 'GET':
        return render_template('signup.html')

    service_num = request.form.get('service_number', '').strip()
    name = request.form.get('full_name', '').strip()
    rank_designation = request.form.get('rank', '').strip()
    role_clearance = request.form.get('role_permissions', '').strip()
    plain_password = request.form.get('password', '').strip()

    existing_user = db.session.query(User).filter_by(service_number=service_num).first()
    if existing_user:
        flash('Registration Aborted: Target service number is already registered inside systems registry.', 'danger')
        return redirect(url_for('process_signup'))

    try:
        new_user = User(
            service_number=service_num,
            full_name=name,
            rank=rank_designation,
            role_permissions=role_clearance,
            password_hash=generate_password_hash(plain_password),
            account_status='Active'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Officer user profile provisioned successfully! You can now log into the portal.', 'success')
        return redirect(url_for('login_view'))
    except SQLAlchemyError as signup_db_err:
        db.session.rollback()
        print(f"[CRITICAL ERROR] Core registration handler crash details: {signup_db_err}")
        flash('Relational database transaction error. Account creation sequence aborted.', 'danger')
        return redirect(url_for('process_signup'))


# =========================================================================
# ROUTING LOGIC LAYER C: TRANSACTIONAL COMMAND DASHBOARDS WORKSPACE
# =========================================================================

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Access Denied: Please authenticate security credentials.', 'danger')
        return redirect(url_for('login_view'))

    user_role = session.get('role')
    current_user = db.session.query(User).get(session['user_id'])
    today = datetime.now(timezone.utc).date()

    try:
        # 1. Automated Overdue Scanner: Flag any active deployment past its return date
        expired_logs = db.session.query(DeploymentLog).filter(
            DeploymentLog.log_status == 'Active',
            DeploymentLog.expected_return_date < today
        ).all()

        if expired_logs:
            for item in expired_logs:
                item.log_status = 'Overdue'
            db.session.commit()

        available_count = db.session.query(FirearmInventory).filter_by(operational_status='Available').count()
        deployed_count = db.session.query(FirearmInventory).filter_by(operational_status='Deployed').count()

        if user_role in ['Armourer', 'System Administrator']:
            logs = db.session.query(DeploymentLog).filter(DeploymentLog.log_status.in_(['Active', 'Overdue'])).all()
            my_ammo = []
        else:
            logs = db.session.query(DeploymentLog).filter(
                DeploymentLog.officer_id == session['user_id'],
                DeploymentLog.log_status.in_(['Active', 'Overdue'])
            ).all()

            my_ammo = db.session.query(AmmoTransaction).filter(
                AmmoTransaction.transaction_type == 'Distribution',
                db.or_(
                    AmmoTransaction.target_unit.ilike(f"%{current_user.full_name}%"),
                    AmmoTransaction.target_unit.ilike(f"%{current_user.service_number}%")
                )
            ).order_by(AmmoTransaction.timestamp.desc()).all()

        overdue_count = sum(1 for log in logs if log.log_status == 'Overdue')

    except SQLAlchemyError:
        db.session.rollback()
        available_count = deployed_count = overdue_count = 0
        logs, my_ammo = [], []

    return render_template(
        'dashboard.html',
        user=current_user,
        available=available_count,
        deployed=deployed_count,
        active_logs=logs,
        my_ammo=my_ammo,
        overdue_count=overdue_count
    )

@app.route('/process_checkout', methods=['POST'])
def process_checkout():
    """Executes secure, atomic transactions to guarantee hardware lifecycle tracking data accuracy."""
    if session.get('role') != 'Armourer':
        flash('Security Access Violation: Operational action requires certified Armourer privileges.', 'danger')
        return redirect(url_for('dashboard'))

    officer_num = request.form.get('officer_service_number', '').strip()
    weapon_serial = request.form.get('weapon_serial', '').strip()
    operation = request.form.get('operation', '').strip()
    return_date_str = request.form.get('expected_return', '').strip()

    officer = db.session.query(User).filter_by(service_number=officer_num).first()
    weapon = db.session.query(FirearmInventory).filter_by(serial_number=weapon_serial,
                                                          operational_status='Available').first()

    if not officer:
        flash('Operational Capture Error: Officer Service ID not found inside RDU files.', 'danger')
        return redirect(url_for('dashboard'))
    if not weapon:
        flash('Logistical Tracking Error: Firearm serial invalid or currently deployed to field base.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        new_log = DeploymentLog(
            officer_id=officer.id,
            firearm_id=weapon.id,
            armourer_id=session['user_id'],
            purpose_operation=operation,
            expected_return_date=datetime.strptime(return_date_str, '%Y-%m-%d').date()
        )
        weapon.operational_status = 'Deployed'

        db.session.add(new_log)
        db.session.commit()
        flash(f'Asset tactical checkout committed successfully. Serial {weapon_serial} signed to Officer.', 'success')
    except (ValueError, SQLAlchemyError):
        db.session.rollback()
        flash('Transaction Pipeline Fault: Database error or invalid date format. Rollback applied.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/process_checkin/<int:log_id>', methods=['POST'])
def process_checkin(log_id):
    """Closes an active deployment log, updates cumulative rounds fired, and checks maintenance thresholds."""
    if 'user_id' not in session:
        return redirect(url_for('login_view'))

    if session.get('role') not in ['Armourer', 'System Administrator']:
        flash('Security Access Violation: Asset check-in requires certified Armourer privileges.', 'danger')
        return redirect(url_for('dashboard'))

    log_entry = db.session.query(DeploymentLog).get(log_id)
    if not log_entry or log_entry.log_status == 'Returned':
        flash('Logistical Error: Deployment record not found or already closed.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        rounds_fired = int(request.form.get('rounds_fired', 0))
        if rounds_fired < 0:
            raise ValueError("Rounds fired cannot be negative.")
        needs_maintenance = request.form.get('needs_maintenance') == 'yes'

        log_entry.log_status = 'Returned'
        log_entry.checkin_timestamp = datetime.now(timezone.utc)

        weapon = log_entry.firearm
        if weapon:
            weapon.cumulative_rounds_fired = (weapon.cumulative_rounds_fired or 0) + rounds_fired

            # Automatically log expended rounds in the Ammunition Ledger
            if rounds_fired > 0:
                ammo_exp = AmmoTransaction(
                    caliber=weapon.caliber,
                    transaction_type='Expenditure',
                    quantity=rounds_fired,
                    target_unit=f"{log_entry.officer.full_name} ({weapon.serial_number})",
                    reference_voucher=f"CHK-IN-#{log_entry.id}"
                )
                db.session.add(ammo_exp)

            # Set status to Maintenance if flagged or if cumulative rounds exceed 5,000
            if needs_maintenance or weapon.cumulative_rounds_fired >= 5000:
                weapon.operational_status = 'Maintenance'
                status_msg = f"flagged for MAINTENANCE ({weapon.cumulative_rounds_fired:,} total rounds)"
            else:
                weapon.operational_status = 'Available'
                status_msg = f"returned to Available stock ({weapon.cumulative_rounds_fired:,} total rounds)"

        db.session.commit()
        flash(f'Check-In Complete: Serial {weapon.serial_number} logged {rounds_fired:,} rounds and {status_msg}.', 'success')
    except (ValueError, SQLAlchemyError) as err:
        db.session.rollback()
        print(f"[DB ERROR] Check-in failed: {err}")
        flash('Transaction Error: Please enter a valid non-negative round count.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/deployment-logs')
def deployment_logs():
    """Renders the complete historical audit ledger of all tactical deployments."""
    if 'user_id' not in session:
        flash('Access Denied: Please authenticate security credentials.', 'danger')
        return redirect(url_for('login_view'))

    try:
        all_logs = db.session.query(DeploymentLog).order_by(DeploymentLog.checkout_timestamp.desc()).all()
    except SQLAlchemyError:
        all_logs = []

    return render_template('deployment_logs.html', logs=all_logs)


# =========================================================================
# ROUTING LOGIC LAYER D: FIREARMS & AMMUNITION INVENTORY MANAGEMENT
# =========================================================================

@app.route('/firearms-inventory')
def firearms_inventory():
    """Renders the Arsenal Logistics & Control Center with live PostgreSQL data."""
    if 'user_id' not in session:
        flash('Access Denied: Please authenticate security credentials.', 'danger')
        return redirect(url_for('login_view'))

    try:
        firearms_list = db.session.query(FirearmInventory).all()
        ammo_logs = db.session.query(AmmoTransaction).order_by(AmmoTransaction.timestamp.desc()).all()

        # Calculate live ammunition totals from PostgreSQL records
        acquired_total = sum(log.quantity for log in ammo_logs if log.transaction_type == 'Acquisition')
        distributed_total = sum(log.quantity for log in ammo_logs if log.transaction_type == 'Distribution')
        expended_total = sum(log.quantity for log in ammo_logs if log.transaction_type == 'Expenditure')
        net_reserve = acquired_total - (distributed_total + expended_total)

    except SQLAlchemyError as db_err:
        print(f"[DB ERROR] Failed to fetch inventory: {db_err}")
        firearms_list, ammo_logs = [], []
        acquired_total = distributed_total = expended_total = net_reserve = 0

    return render_template(
        'firearms_inventory.html',
        firearms=firearms_list,
        ammo_logs=ammo_logs,
        acquired=acquired_total,
        distributed=distributed_total,
        expended=expended_total,
        reserve=net_reserve
    )


@app.route('/add_firearm', methods=['POST'])
def add_firearm():
    """Saves a newly acquired firearm permanently into PostgreSQL."""
    if 'user_id' not in session:
        return redirect(url_for('login_view'))

    if session.get('role') not in ['Armourer', 'System Administrator']:
        flash('Security Violation: Only certified Armourers can register new firearms.', 'danger')
        return redirect(url_for('firearms_inventory'))

    serial = request.form.get('serial', '').strip()
    model = request.form.get('model', '').strip()
    f_type = request.form.get('type', '').strip()
    caliber = request.form.get('caliber', '').strip()
    status = request.form.get('status', 'Available').strip()

    existing = db.session.query(FirearmInventory).filter_by(serial_number=serial).first()
    if existing:
        flash(f'Registration Rejected: Serial number {serial} already exists in the armoury.', 'danger')
        return redirect(url_for('firearms_inventory'))

    try:
        new_weapon = FirearmInventory(
            serial_number=serial,
            make_model=model,
            weapon_type=f_type,
            caliber=caliber,
            operational_status=status
        )
        db.session.add(new_weapon)
        db.session.commit()
        flash(f'Firearm {serial} ({model}) permanently registered in database.', 'success')
    except SQLAlchemyError as err:
        db.session.rollback()
        print(f"[DB ERROR] Add firearm failed: {err}")
        flash('Database Error: Could not save firearm record.', 'danger')

    return redirect(url_for('firearms_inventory'))

@app.route('/mark_serviced/<int:firearm_id>', methods=['POST'])
@roles_required('Armourer', 'System Administrator')
def mark_serviced(firearm_id):
    """Returns a firearm from Maintenance back to Available stock after armourer servicing."""
    weapon = db.session.query(FirearmInventory).get(firearm_id)
    if not weapon or weapon.operational_status != 'Maintenance':
        flash('Logistical Error: Firearm not found or not currently in Maintenance.', 'danger')
        return redirect(url_for('firearms_inventory'))

    try:
        weapon.operational_status = 'Available'
        weapon.cumulative_rounds_fired = 0  # Resets service interval counter for the next 5,000-round cycle
        db.session.commit()
        flash(f'Maintenance Complete: Serial {weapon.serial_number} ({weapon.make_model}) returned to Available stock.', 'success')
    except SQLAlchemyError as err:
        db.session.rollback()
        print(f"[DB ERROR] Mark serviced failed: {err}")
        flash('Database Error: Could not update firearm status.', 'danger')

    return redirect(url_for('firearms_inventory'))

@app.route('/log_ammo', methods=['POST'])
def log_ammo():
    """Saves an ammunition acquisition, distribution, or expenditure record into PostgreSQL."""
    if 'user_id' not in session:
        return redirect(url_for('login_view'))

    if session.get('role') not in ['Armourer', 'System Administrator']:
        flash('Security Violation: Only certified Armourers can log ammunition transactions.', 'danger')
        return redirect(url_for('firearms_inventory'))

    t_type = request.form.get('transaction_type', '').strip()
    caliber = request.form.get('caliber', '').strip()
    target = request.form.get('target', '').strip()
    reference = request.form.get('reference', '').strip() or 'N/A'

    try:
        qty = int(request.form.get('quantity', 0))
        if qty <= 0:
            raise ValueError("Quantity must be positive")

        new_tx = AmmoTransaction(
            caliber=caliber,
            transaction_type=t_type,
            quantity=qty,
            target_unit=target,
            reference_voucher=reference
        )
        db.session.add(new_tx)
        db.session.commit()
        flash(f'Ammunition {t_type} of {qty:,} rounds ({caliber}) committed to ledger.', 'success')
    except (ValueError, SQLAlchemyError) as err:
        db.session.rollback()
        print(f"[DB ERROR] Log ammo failed: {err}")
        flash('Transaction Error: Please enter a valid positive quantity.', 'danger')

    return redirect(url_for('firearms_inventory'))

@app.route('/export/deployments')
@roles_required('Armourer', 'System Administrator')
def export_deployments_csv():
    """Exports the complete chain-of-custody deployment history as an Excel-compatible CSV."""
    logs = db.session.query(DeploymentLog).order_by(DeploymentLog.checkout_timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Log ID', 'Officer Service No', 'Officer Name', 'Rank',
        'Firearm Serial', 'Make & Model', 'Mission / Location',
        'Issued By (Armourer)', 'Checkout Timestamp (UTC)',
        'Expected Return Date', 'Check-In Timestamp (UTC)', 'Status'
    ])

    for log in logs:
        writer.writerow([
            log.id,
            log.officer.service_number if log.officer else 'N/A',
            log.officer.full_name if log.officer else 'N/A',
            log.officer.rank if log.officer else 'N/A',
            log.firearm.serial_number if log.firearm else 'N/A',
            log.firearm.make_model if log.firearm else 'N/A',
            log.purpose_operation,
            log.armourer.full_name if log.armourer else 'N/A',
            log.checkout_timestamp.strftime('%Y-%m-%d %H:%M') if log.checkout_timestamp else '',
            log.expected_return_date.strftime('%Y-%m-%d') if log.expected_return_date else '',
            log.checkin_timestamp.strftime('%Y-%m-%d %H:%M') if log.checkin_timestamp else 'In Field',
            log.log_status
        ])

    filename = f"RDU_Deployment_Audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/export/ammo')
@roles_required('Armourer', 'System Administrator')
def export_ammo_csv():
    """Exports the complete ammunition acquisition, distribution, and expenditure ledger as CSV."""
    records = db.session.query(AmmoTransaction).order_by(AmmoTransaction.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Transaction ID', 'Timestamp (UTC)', 'Caliber', 'Transaction Type', 'Quantity (Rounds)', 'Recipient / Batch / Unit', 'Reference Voucher'])

    for r in records:
        signed_qty = r.quantity if r.transaction_type == 'Acquisition' else -r.quantity
        writer.writerow([
            r.id,
            r.timestamp.strftime('%Y-%m-%d %H:%M') if r.timestamp else '',
            r.caliber,
            r.transaction_type,
            signed_qty,
            r.target_unit,
            r.reference_voucher or 'N/A'
        ])

    filename = f"RDU_Ammo_Ledger_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/logout')
def logout():
    """Clears system state storage caches and safely terminates session tokens."""
    session.clear()
    return redirect(url_for('login_view'))


# =========================================================================
# TEMPORARY LOGISTICAL MANAGEMENT ROUTINE: STOCK INVENTORY SEEDER
# Run this once on the live website to stock your armourer shelves with test assets
# =========================================================================
@app.route('/seed-armoury-stock')
def seed_armoury_stock():
    try:
        # Check if items already exist to avoid accidental duplicate records
        existing_stock = db.session.query(FirearmInventory).first()
        if existing_stock:
            return "Armoury Shelves Already Stocked! No injection required.", 200

        # Create three standard-issue field assets for tactical validation
        weapon1 = FirearmInventory(serial_number="RDU-SIG-9081", weapon_type="Pistol", make_model="Sig Sauer P320",
                                   caliber="9x19mm", operational_status="Available")
        weapon2 = FirearmInventory(serial_number="RDU-AR-4402", weapon_type="Assault Rifle", make_model="M4A1 Carbine",
                                   caliber="7.62x51mm", operational_status="Available")
        weapon3 = FirearmInventory(serial_number="RDU-GLK-1793", weapon_type="Support Weapon", make_model="GPMG 17",
                                   caliber="7.62x55mm", operational_status="Available")

        db.session.add_all([weapon1, weapon2, weapon3])
        db.session.commit()
        return "Logistical Injection Successful! 3 Active Firearms Added to Live PostgreSQL.", 200

    except Exception as seed_err:
        db.session.rollback()
        return f"Logistical Injection Pipeline Failed: {seed_err}", 500
# =========================================================================
# STANDARD EXECUTION ROUTINE LAYER: LOCAL TESTING ENVIRONMENT ONLY
# =========================================================================
if __name__ == '__main__':
    app.run(debug=True)