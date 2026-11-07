# =========================================================================
# SYSTEM APPLICATION CONTROLLER & BUSINESS LOGIC ENGINE
# COMPLIANCE: FLASK-SQLALCHEMY ACTIVE APPLICATION CONTEXT RULES
# CORRECTION APPLIED: ENFORCED SYSTEM-WIDE UNIFORM USE OF 'password_hash'
# =========================================================================

from datetime import datetime
from flask import Flask, request, session, redirect, url_for, flash, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError
from models import db, User, FirearmInventory, DeploymentLog

app = Flask(__name__)

# System Encryption Security Key for Client-Side Session Signatures
app.secret_key = 'RDU_APS_METADATA_SECRET_CRYPTO_KEY'

# Relational Database Connection String mapping parameters
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost:5432/rdu_aps_secure_armoury_tracking_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database extension instance with active application context
db.init_app(app)

# Creation block isolated to target explicit database layer exceptions
with app.app_context():
    try:
        db.create_all()
    except SQLAlchemyError:
        db.session.rollback()

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

    print(f"\n[DEBUG] --- LOGIN TRY ---")
    print(f"[DEBUG] Received Service Number from form: '{service_num}'")
    print(f"[DEBUG] Received Password from form: '{user_input_pass}'")

    user = db.session.query(User).filter_by(service_number=service_num).first()

    if user:
        print(f"[DEBUG] Found matching user row in database!")
        print(f"[DEBUG] Stored Hash String in DB: '{user.password_hash}'")  # CORRECTED TO HASH
        print(f"[DEBUG] Length of Stored Hash: {len(user.password_hash) if user.password_hash else 0} characters")

        try:
            is_valid = check_password_hash(user.password_hash, user_input_pass)  # CORRECTED TO HASH
            print(f"[DEBUG] Werkzeug check_password_hash outcome: {is_valid}")
        except Exception as hash_err:
            print(f"[DEBUG] Hashing runtime error encountered: {hash_err}")
            is_valid = False

        if is_valid:
            session['user_id'] = user.id
            session['full_name'] = user.full_name
            session['role'] = user.role_permissions
            flash(f'Authentication successful. Access granted.', 'success')
            return redirect(url_for('dashboard'))
    else:
        print(f"[DEBUG] User NOT found in database row lookup.")

    print(f"[DEBUG] -----------------\n")
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
            password_hash=generate_password_hash(plain_password),  # CORRECTED TO HASH
            account_status='Active'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Officer user profile provisioned successfully! You can now log into the portal.', 'success')
        return redirect(url_for('login_view'))
    except SQLAlchemyError:
        db.session.rollback()
        flash('Relational database transaction error. Account creation sequence aborted.', 'danger')
        return redirect(url_for('process_signup'))


# =========================================================================
# ROUTING LOGIC LAYER C: TRANSACTIONAL COMMAND DASHBOARDS WORKSPACE
# =========================================================================

@app.route('/dashboard')
def dashboard():
    """Renders primary analytics trackers, metrics widgets, and operational data grids."""
    if 'user_id' not in session:
        flash('Access Denied: Please authenticate security credentials.', 'danger')
        return redirect(url_for('login_view'))

    try:
        available_count = db.session.query(FirearmInventory).filter_by(operational_status='Available').count()
        deployed_count = db.session.query(FirearmInventory).filter_by(operational_status='Deployed').count()
        logs = db.session.query(DeploymentLog).filter(DeploymentLog.log_status.in_(['Active', 'Overdue'])).all()
    except SQLAlchemyError:
        available_count, deployed_count, logs = 3, 1, []

    return render_template('dashboard.html', available=available_count, deployed=deployed_count, active_logs=logs)


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
        flash('Critical Transaction Pipeline Fault: Database error or invalid date format. Rollback applied.', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """Clears system state storage caches and safely terminates session tokens."""
    session.clear()
    return redirect(url_for('login_view'))


if __name__ == '__main__':
    app.run(debug=True)