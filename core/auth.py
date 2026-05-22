import pyotp
import logging
import time
import secrets
import string
import threading
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
from core.database import db, User, PasswordReset
from core.security import sec_manager
from core.admin import send_notification_email
from core.sdk import WinHubCore

log = logging.getLogger("winhub.auth")
auth_bp = Blueprint('auth', __name__)

def audit_auth(username, action, details, status="Success", user_id=None):
    WinHubCore.audit(
        user_id=user_id,
        username=username,
        module="Auth",
        action=action,
        details=details,
        status=status
    )

@auth_bp.route('/login', methods=['GET'])
def login_page():
    if session.get('logged_in'):
        return redirect(url_for('core_routes.dashboard'))
    return render_template('login.html')

@auth_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    otp_code = data.get('otp', '').strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.is_active:
        log.warning(f"Failed login attempt for unknown or inactive user: {username}")
        # Фіксуємо невдалий вхід в Аудит
        audit_auth(username, "Login Failed", {"reason": "unknown_or_locked"}, "Denied")
        return jsonify({"success": False, "message": "Invalid credentials or account is locked."}), 401

    if not sec_manager.verify_password(user.password_hash, password):
        log.warning(f"Invalid password for user: {username}")
        # Фіксуємо помилку пароля
        audit_auth(username, "Login Failed", {"reason": "invalid_password"}, "Denied")
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    if user.totp_secret:
        # Підтримка як зашифрованих так і незашифрованих TOTP секретів
        try:
            dec_secret = sec_manager.decrypt_data(user.totp_secret)
            totp = pyotp.TOTP(dec_secret if dec_secret else user.totp_secret)
        except:
            totp = pyotp.TOTP(user.totp_secret)
            
        if not totp.verify(otp_code, valid_window=1):
            log.warning(f"Invalid 2FA code for user: {username}")
            # Фіксуємо помилку 2FA
            audit_auth(username, "Login Failed", {"reason": "invalid_2fa"}, "Denied", user_id=user.id)
            return jsonify({"success": False, "message": "Invalid Authenticator code."}), 401

    session.clear()
    session['logged_in'] = True
    session['user_id'] = user.id
    session['username'] = user.username
    session['is_admin'] = user.is_admin
    session['login_at'] = time.time()
    session['last_activity'] = time.time()
    session['csrf_token'] = secrets.token_urlsafe(32)
    session.permanent = True
    
    # Фіксуємо УСПІШНИЙ вхід в Аудит
    audit_auth(username, "Login Success", {"is_admin": bool(user.is_admin)}, "Success", user_id=user.id)
    
    log.info(f"User '{username}' logged in successfully.")
    return jsonify({"success": True, "message": "Login successful", "redirect": "/dashboard"})

@auth_bp.route('/api/auth/forgot', methods=['POST'])
def forgot_password():
    data = request.json or {}
    email = str(data.get('email', '')).strip().lower()
    
    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": True, "message": "If this email is registered, a recovery code has been sent."}), 200

    PasswordReset.query.filter_by(user_id=user.id).delete()
    code = ''.join(secrets.choice(string.digits) for _ in range(6))
    
    reset_record = PasswordReset(
        user_id=user.id,
        code=code,
        expires_at=time.time() + 300  # 5 minutes
    )
    db.session.add(reset_record)
    
    db.session.commit()
    audit_auth(user.username, "Password Reset Requested", {"email": email}, "Warning", user_id=user.id)
    
    body = f"Hello {user.username},\n\nYour WinHUB password recovery code is: {code}\nThis code is valid for 5 minutes."
    threading.Thread(target=send_notification_email, args=("Password Recovery", email, body, True)).start()
    
    return jsonify({"success": True, "message": "If this email is registered, a recovery code has been sent."})

@auth_bp.route('/api/auth/reset', methods=['POST'])
def reset_password():
    data = request.json or {}
    email = str(data.get('email', '')).strip().lower()
    code = str(data.get('code', '')).strip()
    new_password = str(data.get('new_password', ''))
    
    if not new_password or len(new_password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters long."}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"success": False, "message": "Invalid request."}), 401

    record = PasswordReset.query.filter_by(user_id=user.id).first()
    
    if not record or record.expires_at < time.time():
        if record:
            db.session.delete(record)
            db.session.commit()
        return jsonify({"success": False, "message": "Invalid or expired code."}), 401
        
    if record.attempts >= 3:
        db.session.delete(record)
        db.session.commit()
        return jsonify({"success": False, "message": "Too many failed attempts. Request a new code."}), 403
        
    if record.code != code:
        record.attempts += 1
        db.session.commit()
        left = 3 - record.attempts
        return jsonify({"success": False, "message": f"Invalid code. Attempts left: {left}"}), 401
        
    user.password_hash = sec_manager.hash_password(new_password)
    user.force_2fa_setup = True 
    db.session.delete(record) 
    
    db.session.commit()
    audit_auth(user.username, "Password Changed", {"via": "recovery_code"}, "Success", user_id=user.id)
    
    return jsonify({"success": True, "message": "Password reset successfully. You can now log in."})

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    user = session.get('username', 'Unknown')
    reason = request.args.get('reason') or 'manual'
    if session.get('logged_in') and not session.get('api_key_auth'):
        audit_auth(user, "Logout", {"reason": reason}, "Success", user_id=session.get('user_id'))
    session.clear()
    return redirect(url_for('auth.login_page'))
