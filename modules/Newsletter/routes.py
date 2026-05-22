import os
import json
import logging
import traceback
import threading
import urllib.request
import urllib.parse
import subprocess
import tempfile
import time
import base64
import smtplib
import ssl
from email.mime.text import MIMEText
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify, session, render_template, current_app
from flask_socketio import join_room
from cryptography.fernet import Fernet
from core.database import db, User, Task
from core import socketio
from core.sdk import WinHubCore
from core.config import Config
from core.permissions import has_module_access, has_permission, user_permissions

log = logging.getLogger("winhub.newsletter")

newsletter_bp = Blueprint('newsletter', __name__, template_folder='templates')

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("NEWSLETTER_DATA_DIR") or os.path.join(Config.DATA_DIR, "newsletter")
LISTS_DIR = os.path.join(DATA_DIR, "lists")
SMTP_FILE = os.path.join(DATA_DIR, "smtp_profiles.json")
DEFAULT_RECIPIENT_DOMAIN = os.environ.get("NEWSLETTER_RECIPIENT_DOMAIN", "@syneforge.com")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LISTS_DIR, exist_ok=True)

@socketio.on('join_newsletter_logs')
def join_newsletter_logs():
    user_id = session.get('user_id')
    if user_id:
        join_room(str(user_id))

def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

def hidden_subprocess_kwargs():
    return {"creationflags": 0x08000000} if os.name == "nt" else {}

def normalize_recipient(value):
    recipient = str(value or "").strip()
    if not recipient:
        return ""
    if "@" in recipient:
        return recipient
    domain = DEFAULT_RECIPIENT_DOMAIN.strip()
    if domain and not domain.startswith("@"):
        domain = f"@{domain}"
    return f"{recipient}{domain}"

# --- Encryption Helper for SMTP Passwords ---
def get_cipher():
    """Generates a Fernet cipher based on the app's SECRET_KEY"""
    secret = current_app.config['SECRET_KEY']
    key = base64.urlsafe_b64encode(secret.encode('utf-8')[:32].ljust(32, b'='))
    return Fernet(key)

def encrypt_pass(password):
    return get_cipher().encrypt(password.encode('utf-8')).decode('utf-8')

def decrypt_pass(encrypted_password):
    try:
        return get_cipher().decrypt(encrypted_password.encode('utf-8')).decode('utf-8')
    except:
        return ""

# --- Helper Functions ---
def load_smtp_profiles():
    if not os.path.exists(SMTP_FILE): return {}
    try:
        with open(SMTP_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return {}

def save_smtp_profiles(data):
    ensure_parent_dir(SMTP_FILE)
    with open(SMTP_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def load_lists():
    lists = {}
    for filename in os.listdir(LISTS_DIR):
        if filename.endswith(".json"):
            list_name = filename[:-5]
            filepath = os.path.join(LISTS_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    lists[list_name] = json.load(f)
            except:
                lists[list_name] = []
    return lists

# --- Access Protection ---
@newsletter_bp.before_request
def check_access():
    user = User.query.get(session.get('user_id'))
    if not user: return jsonify({"success": False}), 401
    if not has_module_access(user, 'Newsletter'):
        return "Access Denied", 403

def current_user():
    return User.query.get(session.get('user_id'))

def require_permission(permission_id):
    if not has_permission(current_user(), "Newsletter", permission_id):
        return jsonify({"success": False, "message": "Permission denied"}), 403
    return None

# --- Routes ---
@newsletter_bp.route("/module/newsletter")
def index():
    permissions = user_permissions(current_user(), "Newsletter")
    return render_template('newsletter_index.html', username=session.get('username'), is_admin=session.get('is_admin'), permissions=permissions)

@newsletter_bp.route("/api/newsletter/config", methods=["GET"])
def get_config():
    can_manage_smtp = has_permission(current_user(), "Newsletter", "manage_smtp")
    can_manage_lists = has_permission(current_user(), "Newsletter", "manage_lists")
    profiles = load_smtp_profiles()
    
    senders = []
    for email, conf in profiles.items():
        if can_manage_smtp:
            senders.append({
                "email": email, 
                "host": conf.get("host", ""), 
                "port": conf.get("port", 587),
                "keyserver": conf.get("keyserver", "")
            })
        else:
            senders.append({"email": email})
            
    all_lists = load_lists()
    
    # Маскуємо дані списків для звичайних користувачів
    if not can_manage_lists:
        all_lists = {k: [] for k in all_lists.keys()}
            
    return jsonify({"success": True, "senders": senders, "lists": all_lists})

@newsletter_bp.route("/api/newsletter/smtp", methods=["POST"])
def manage_smtp():
    denied = require_permission("manage_smtp")
    if denied: return denied
        
    data = request.json or {}
    action = data.get("action")
    email = data.get("email", "").strip()
    
    if not email: return jsonify({"success": False, "message": "Email is required."}), 400
    
    profiles = load_smtp_profiles()
    
    if action == "add":
        host = data.get("host", "").strip()
        port = data.get("port", 587)
        password = data.get("password", "")
        keyserver = data.get("keyserver", "").strip()
        
        if not host or not password:
            return jsonify({"success": False, "message": "Host and Password are required."}), 400
            
        profiles[email] = {
            "host": host,
            "port": int(port),
            "password": encrypt_pass(password),
            "keyserver": keyserver
        }
        save_smtp_profiles(profiles)
        
    elif action == "delete":
        if email in profiles:
            del profiles[email]
            save_smtp_profiles(profiles)
            
    return jsonify({"success": True, "message": "SMTP configuration updated."})

@newsletter_bp.route("/api/newsletter/lists", methods=["POST"])
def save_list():
    denied = require_permission("manage_lists")
    if denied: return denied

    data = request.json or {}
    list_name = data.get("list_name", "").strip()
    users = data.get("users", [])
    
    if not list_name: return jsonify({"success": False, "message": "List name is required."}), 400
    
    clean_users = [u.strip() for u in users if u.strip()]
    filepath = os.path.join(LISTS_DIR, f"{list_name}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(clean_users, f, indent=4)
        
    return jsonify({"success": True, "message": "List saved successfully."})

@newsletter_bp.route("/api/newsletter/lists/<list_name>", methods=["DELETE"])
def delete_list(list_name):
    denied = require_permission("manage_lists")
    if denied: return denied

    filepath = os.path.join(LISTS_DIR, f"{list_name}.json")
    if os.path.exists(filepath): os.remove(filepath)
    return jsonify({"success": True})

@newsletter_bp.route("/api/newsletter/send", methods=["POST"])
def send_newsletter():
    denied = require_permission("send_campaigns")
    if denied: return denied
    data = request.json or {}
    sender_email = data.get("sender", "").strip()
    selected_lists = data.get("lists", [])
    subject = data.get("subject", "Newsletter").strip()
    body = data.get("body", "").strip()
    use_gpg = bool(data.get("use_gpg", True))
    
    user_id = session.get('user_id')
    room_id = str(user_id)
    is_admin = session.get('is_admin', False)
    
    if not sender_email or not selected_lists or not body:
        return jsonify({"success": False, "message": "Please fill in all required fields."}), 400

    profiles = load_smtp_profiles()
    if sender_email not in profiles:
        return jsonify({"success": False, "message": "Sender profile not found."}), 404
        
    all_lists = load_lists()
    target_users = set()
    for lname in selected_lists:
        if lname in all_lists:
            for item in all_lists[lname]:
                recipient = normalize_recipient(item)
                if recipient:
                    target_users.add(recipient)
            
    if not target_users:
        return jsonify({"success": False, "message": "No recipients found in the selected lists."}), 400

    # Create Task in DB
    task_id = str(uuid.uuid4())
    log_file = os.path.join(current_app.config['DATA_DIR'], 'logs', f"task_{task_id}.log")
    ensure_parent_dir(log_file)
    
    targets_db = ", ".join(selected_lists)
    if len(targets_db) > 50: targets_db = targets_db[:47] + "..."
    
    new_task = Task(
        id=task_id, user_id=user_id, module_name="Newsletter",
        action="Send Campaign", targets=targets_db, status="Running", log_file=log_file
    )
    db.session.add(new_task)
    db.session.commit()

    try:
        WinHubCore.audit(
            user_id=user_id,
            username=session.get('username'),
            module="Newsletter",
            action="Send Campaign",
            details={
                "sender": sender_email,
                "lists": selected_lists,
                "recipients_count": len(target_users),
                "use_gpg": use_gpg,
            },
            status="Success"
        )
    except Exception as e:
        log.error(f"Failed to audit Newsletter campaign start: {e}")

    # Background Execution
    app_context = current_app._get_current_object()
    thread = threading.Thread(target=bg_send_execution, args=(
        app_context, task_id, sender_email, profiles[sender_email], list(target_users), subject, body, use_gpg, log_file, room_id, is_admin
    ))
    thread.daemon = True
    thread.start()

    return jsonify({"success": True})


# --- GPG Functions ---
def check_gpg_key_exists(gpg_path, email):
    cmd = [gpg_path, "--batch", "--list-keys", email]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5, **hidden_subprocess_kwargs())
        return proc.returncode == 0
    except Exception:
        return False

def validate_gpg(gpg_path):
    if not gpg_path or not os.path.exists(gpg_path):
        return False, f"GPG executable not found at '{gpg_path}'"
    try:
        proc = subprocess.run([gpg_path, "--version"], capture_output=True, text=True, timeout=5, **hidden_subprocess_kwargs())
        if proc.returncode != 0:
            return False, proc.stderr.strip() or "GPG version check failed"
        return True, "GPG is available"
    except Exception as e:
        return False, str(e)

def fetch_gpg_key(gpg_path, keyserver, email):
    """Миттєве завантаження ключа через стандартний HTTPS API сервера SKS (Обхід багів dirmngr)"""
    try:
        base_url = keyserver.replace("hkps://", "https://").replace("hkp://", "http://")
        api_url = f"{base_url}/pks/lookup?op=get&options=mr&search={urllib.parse.quote(email)}"
        
        # ІГНОРУВАННЯ ПОМИЛОК SSL (Для самопідписаних сертифікатів)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Намагаємося завантажити ключ з HTTP/HTTPS
        try:
            req = urllib.request.Request(api_url, headers={'User-Agent': 'Mozilla/5.0 (WinHUB)'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                key_data = response.read().decode('utf-8')
        except Exception as e:
            return False, f"HTTP Fetch Error: {str(e)}"

        # Перевіряємо, чи отримали ми саме ключ
        if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in key_data:
            return False, "Invalid response: No PGP public key block found in server reply."

        # Зберігаємо у тимчасовий файл
        fd, tmp_path = tempfile.mkstemp(suffix=".asc")
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(key_data)

        # Спокійно імпортуємо локально в GPG
        try:
            cmd_import = [gpg_path, "--batch", "--yes", "--import", tmp_path]
            proc = subprocess.run(cmd_import, capture_output=True, text=True, timeout=10, **hidden_subprocess_kwargs())
        except FileNotFoundError:
            os.remove(tmp_path)
            return False, f"GPG executable not found at '{gpg_path}'"

        # Видаляємо тимчасовий файл
        try: os.remove(tmp_path)
        except: pass

        if proc.returncode == 0:
            return True, "Key imported successfully"
        else:
            err_msg = proc.stderr.strip() if proc.stderr else "Unknown import error"
            return False, f"GPG Import returned exit code {proc.returncode}: {err_msg}"
    except Exception as e:
        log.error(f"GPG HTTP Fetch Error: {str(e)}")
        return False, f"System Error: {str(e)}"

def encrypt_with_gpg(gpg_path, recipient_email, body):
    unique_id = str(time.time()).replace(".", "")
    tmp_in = os.path.join(tempfile.gettempdir(), f"nl_{unique_id}.txt")
    tmp_out = tmp_in + ".asc"
    
    try:
        with open(tmp_in, 'w', encoding='utf-8') as f: f.write(body)
            
        # УВАГА: Видалено шифрування для відправника (-r sender_email), 
        # оскільки відсутність його ключа блокує розсилку та викликає таймаути
        cmd = [gpg_path, "--batch", "--yes", "--trust-model", "always",
               "--encrypt", "--armor", "-r", recipient_email,
               "-o", tmp_out, tmp_in]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL, **hidden_subprocess_kwargs())
                              
        if proc.returncode != 0:
            err_msg = proc.stderr.strip() if proc.stderr else "Unknown GPG Error"
            return False, f"GPG Exit {proc.returncode}: {err_msg}"
            
        if not os.path.exists(tmp_out): 
            return False, "Encryption file not generated"
            
        with open(tmp_out, 'r', encoding='utf-8') as f: encrypted_body = f.read()
        return True, encrypted_body
        
    except subprocess.TimeoutExpired:
        return False, "GPG encryption timed out after 15 seconds"
    except Exception as e:
        return False, f"Exception: {str(e)}"
    finally:
        for f in [tmp_in, tmp_out]:
            if os.path.exists(f): 
                try: os.remove(f)
                except: pass

# --- Background Worker ---
def bg_send_execution(app, task_id, sender_email, smtp_config, target_users, subject, body, use_gpg, log_file, room_id, is_admin):
    timestamp = datetime.utcnow().strftime("[%Y-%m-%d %H:%M:%S]")
    ensure_parent_dir(log_file)
    
    def emit_and_write(full_line, public_line=None):
        ensure_parent_dir(log_file)
        with open(log_file, "a", encoding="utf-8") as f: 
            f.write(full_line + "\n")
            
        display_line = public_line if public_line is not None else full_line
        
        if display_line != "__HIDE__":
            public_log_file = log_file.replace(".log", "_public.log")
            ensure_parent_dir(public_log_file)
            with open(public_log_file, "a", encoding="utf-8") as f:
                f.write(display_line + "\n")
        
        actual_emit = full_line if is_admin else display_line
        if actual_emit != "__HIDE__":
            socketio.emit('log_update', {'data': actual_emit}, to=room_id)

    with app.app_context():
        server = None
        try:
            keyserver = smtp_config.get('keyserver', '').strip()
            use_gpg = bool(use_gpg)
            
            emit_and_write(f"========== [ {timestamp} ] NEWSLETTER CAMPAIGN ==========")
            emit_and_write(f"--- 📤 Sender: {sender_email}")
            emit_and_write(f"--- 👥 Recipients: {len(target_users)}", "__HIDE__")
            emit_and_write(f"--- 🔒 GPG Encryption: {'ENABLED' if use_gpg else 'DISABLED'}")
            
            if keyserver:
                emit_and_write(f"--- 🌐 Keyserver Fallback: {keyserver}", "__HIDE__")
                
            emit_and_write(f"----------------------------------------------------------\n")
            
            # Строге зчитування з .env напряму (бо Flask config може не містити цього ключа)
            gpg_path = app.config.get('GPG_PATH') or os.environ.get('GPG_PATH', 'gpg')
            if use_gpg:
                gpg_ok, gpg_message = validate_gpg(gpg_path)
                if not gpg_ok:
                    emit_and_write(f"❌ [CRITICAL ERROR] GPG unavailable: {gpg_message}", "❌ [CRITICAL ERROR] GPG is unavailable. Sending stopped.")
                    raise Exception("GPG unavailable")
            
            success_count = 0
            error_count = 0
            failure_reasons = {}

            emit_and_write(f"⏳ Connecting to SMTP server ({smtp_config['host']}:{smtp_config['port']})...", "⏳ Connecting to mail server...")
            try:
                server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
                server.starttls()
                decrypted_pass = decrypt_pass(smtp_config['password'])
                server.login(sender_email, decrypted_pass)
                emit_and_write(f"✅ SMTP Authentication Successful.\n", "✅ Mail server connection established.\n")
            except Exception as e:
                emit_and_write(f"❌ [CRITICAL ERROR] SMTP Connection Failed: {str(e)}", "❌ [CRITICAL ERROR] Mail server connection failed. Contact an administrator.")
                raise Exception("SMTP Authentication failed")

            emit_and_write(f"🚀 Starting dispatch to {len(target_users)} recipients...", "⏳ Sending emails...\n")

            # Sending loop
            for idx, recipient in enumerate(sorted(target_users), 1):
                final_body = body
                if use_gpg:
                    key_exists = check_gpg_key_exists(gpg_path, recipient)
                    
                    if not key_exists and keyserver:
                        emit_and_write(f"[{idx}/{len(target_users)}] ⚠️ Local key missing for {recipient}. Fetching from keyserver...", "__HIDE__")
                        fetch_success, fetch_msg = fetch_gpg_key(gpg_path, keyserver, recipient)
                        if fetch_success:
                            emit_and_write(f"   🔑 Key imported successfully.", "__HIDE__")
                            key_exists = True
                        else:
                            emit_and_write(f"   ❌ Failed to fetch key from {keyserver}. Reason: {fetch_msg}", "__HIDE__")

                    if not key_exists:
                        emit_and_write(f"[{idx}/{len(target_users)}] ❌ Failed: {recipient} (Encryption Error: Missing public key)", "__HIDE__")
                        error_count += 1
                        failure_reasons["Missing GPG Key"] = failure_reasons.get("Missing GPG Key", 0) + 1
                        continue
                        
                    is_encrypted, final_body = encrypt_with_gpg(gpg_path, recipient, body)
                    
                    if not is_encrypted:
                        emit_and_write(f"[{idx}/{len(target_users)}] ❌ Failed: {recipient} (Encryption Error: {final_body})", "__HIDE__")
                        error_count += 1
                        failure_reasons["GPG Encryption Error"] = failure_reasons.get("GPG Encryption Error", 0) + 1
                        continue
                else:
                    emit_and_write(f"[{idx}/{len(target_users)}] ⚠️ Sending without GPG encryption: {recipient}", "__HIDE__")
                
                try:
                    msg = MIMEText(final_body, 'plain', 'utf-8')
                    msg['Subject'] = subject
                    msg['From'] = sender_email
                    msg['To'] = recipient
                    server.send_message(msg)
                    emit_and_write(f"[{idx}/{len(target_users)}] ✅ Sent: {recipient}", "__HIDE__")
                    success_count += 1
                except Exception as e:
                    emit_and_write(f"[{idx}/{len(target_users)}] ❌ Failed: {recipient} (SMTP Send Error)", "__HIDE__")
                    error_count += 1
                    failure_reasons["SMTP Connection/Send Error"] = failure_reasons.get("SMTP Connection/Send Error", 0) + 1
                
                time.sleep(0.01)

            if server:
                server.quit()
                server = None
            
            # --- FINAL CAMPAIGN SUMMARY ---
            emit_and_write(f"\n==================================================", "__HIDE__")
            emit_and_write(f"📊 CAMPAIGN EXECUTION SUMMARY", "__HIDE__")
            emit_and_write(f"==================================================", "__HIDE__")
            
            emit_and_write(f"✅ Total Successfully Sent: {success_count}", "__HIDE__")
            emit_and_write(f"❌ Total Failed: {error_count}", "__HIDE__")
            
            if error_count == 0:
                emit_and_write("✅ Campaign completed successfully.", "✅ Campaign completed successfully.")
            else:
                emit_and_write("⚠️ Campaign completed with errors.", "⚠️ Campaign completed with errors. Contact an administrator.")

            if error_count > 0:
                emit_and_write(f"\nFailure Breakdown:", "__HIDE__")
                for reason, count in failure_reasons.items():
                    emit_and_write(f"   - {reason}: {count}", "__HIDE__")
            emit_and_write(f"==================================================", "__HIDE__")
            
            task = Task.query.get(task_id)
            if task:
                task.status = "Success" if error_count == 0 else "Warning"
                task.ended_at = datetime.utcnow()
                db.session.commit()
            try:
                WinHubCore.audit(
                    module="Newsletter",
                    action="Campaign Finished",
                    details={
                        "sender": sender_email,
                        "recipients_count": len(target_users),
                        "success_count": success_count,
                        "error_count": error_count,
                        "use_gpg": use_gpg,
                    },
                    status="Success" if error_count == 0 else "Warning"
                )
            except Exception as audit_error:
                log.error(f"Failed to audit Newsletter campaign finish: {audit_error}")
                
        except Exception as e:
            log.error(f"Newsletter Script Error: {traceback.format_exc()}")
            try:
                emit_and_write(f"\n❌ [CRITICAL ERROR] {str(e)}", f"\n❌ [CRITICAL ERROR] Sending was interrupted. Contact an administrator.")
            except Exception as log_error:
                log.error(f"Failed to write Newsletter error log: {log_error}")
            task = Task.query.get(task_id)
            if task:
                task.status = "Error"
                task.ended_at = datetime.utcnow()
                db.session.commit()
            try:
                WinHubCore.audit(
                    module="Newsletter",
                    action="Campaign Failed",
                    details={
                        "sender": sender_email,
                        "recipients_count": len(target_users),
                        "error": str(e),
                        "use_gpg": use_gpg,
                    },
                    status="Error"
                )
            except Exception as audit_error:
                log.error(f"Failed to audit Newsletter campaign failure: {audit_error}")
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
