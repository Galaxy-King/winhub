import os
import json
import secrets
import logging
import hmac
import hashlib
import ipaddress
from datetime import datetime
from flask import Blueprint, request, jsonify
from core.database import db, Endpoint, AgentTask, RegistrationHistory, TelemetryHistory, ConnectionIpHistory, EndpointGroup, EndpointMetric, TriggerRule, User, TaskTemplate
from core.security import sec_manager
from core.sdk import WinHubCore
from core.config import Config

agent_gateway_bp = Blueprint('agent_gateway', __name__, url_prefix='/api/agent')
log = logging.getLogger("winhub.triggers")

GLOBAL_ENROLLMENT_TOKEN = Config.AGENT_API_KEY

def current_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP", "")
    if real_ip:
        return real_ip.strip()
    return request.remote_addr or ""


def update_agent_connection(agent):
    current_ip = current_client_ip()
    changed = False
    if current_ip and current_ip != (agent.ip_address or ""):
        db.session.add(ConnectionIpHistory(endpoint_id=agent.id, ip_address=current_ip, source="agent"))
        agent.ip_address = current_ip
        changed = True
    return changed

def enrollment_source_allowed(remote_addr):
    allowlist = [item.strip() for item in str(getattr(Config, "AGENT_ENROLLMENT_ALLOWLIST", "") or "").split(",") if item.strip()]
    if not allowlist:
        return True
    try:
        remote_ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False
    for item in allowlist:
        try:
            if "/" in item:
                if remote_ip in ipaddress.ip_network(item, strict=False):
                    return True
            elif remote_ip == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    return False


def sign_task_message(task_id, action, payload):
    body = json.dumps({
        "task_id": task_id,
        "action": action,
        "payload": payload,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    secret = str(Config.AGENT_TASK_HMAC_SECRET or Config.SECRET_KEY).encode("utf-8")
    return hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()


def agent_identity_fingerprint(hw_id, hostname, os_type, network_interfaces):
    macs = []
    if isinstance(network_interfaces, list):
        for item in network_interfaces:
            if isinstance(item, dict):
                mac = str(item.get("mac") or "").strip().upper()
                if mac:
                    macs.append(mac)
    source = json.dumps({
        "hw_id": hw_id,
        "hostname": hostname,
        "os_type": os_type,
        "macs": sorted(set(macs)),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def find_approved_duplicate_endpoint(hw_id, hostname, source_ip, fingerprint):
    approved = Endpoint.query.filter(
        Endpoint.id != hw_id,
        Endpoint.approval_status == "Approved"
    ).all()
    for endpoint in approved:
        reasons = []
        if hostname and endpoint.hostname and hostname == endpoint.hostname:
            reasons.append("hostname")
        if source_ip and endpoint.ip_address and source_ip == endpoint.ip_address:
            reasons.append("connection_ip")
        if fingerprint and getattr(endpoint, "identity_fingerprint", None) == fingerprint:
            reasons.append("identity")
        if "identity" in reasons or ("hostname" in reasons and "connection_ip" in reasons):
            return endpoint, reasons
    return None, []


def should_adopt_duplicate_enrollment(reasons):
    reason_set = set(reasons or [])
    return "identity" in reason_set or {"hostname", "connection_ip"}.issubset(reason_set)


def adopt_duplicate_endpoint_identity(existing_endpoint, new_hw_id, raw_token, data, source_ip, fingerprint, network_info, host_info, agent_version):
    old_id = existing_endpoint.id
    groups = list(existing_endpoint.groups)
    adopted = Endpoint(
        id=new_hw_id,
        hostname=data.get("hostname", existing_endpoint.hostname),
        auth_token=raw_token,
        public_key_pem=existing_endpoint.public_key_pem,
        os_version=data.get("os_version", existing_endpoint.os_version),
        os_type=data.get("os_type", existing_endpoint.os_type or "Windows"),
        ip_address=source_ip or existing_endpoint.ip_address,
        approval_status="Approved",
        agent_version=agent_version or existing_endpoint.agent_version,
        network_info=network_info,
        host_info=host_info,
        first_seen=existing_endpoint.first_seen,
        last_enrollment_at=datetime.utcnow(),
        last_enrollment_ip=source_ip,
        enrollment_attempts=int(existing_endpoint.enrollment_attempts or 0) + 1,
        identity_fingerprint=fingerprint,
        identity_warning=None,
        last_seen=datetime.utcnow(),
        is_blocked=bool(existing_endpoint.is_blocked),
    )
    adopted.groups = groups
    db.session.add(adopted)
    db.session.flush()

    AgentTask.query.filter_by(endpoint_id=old_id).update({"endpoint_id": new_hw_id})
    TelemetryHistory.query.filter_by(endpoint_id=old_id).update({"endpoint_id": new_hw_id})
    EndpointMetric.query.filter_by(endpoint_id=old_id).update({"endpoint_id": new_hw_id})
    ConnectionIpHistory.query.filter_by(endpoint_id=old_id).update({"endpoint_id": new_hw_id})
    db.session.add(RegistrationHistory(
        hw_id=new_hw_id,
        hostname=adopted.hostname,
        ip_address=source_ip,
        event_type="Adopted Identity"
    ))
    db.session.add(ConnectionIpHistory(endpoint_id=new_hw_id, ip_address=source_ip, source="identity_adoption"))
    db.session.delete(existing_endpoint)
    return adopted


def trim_result_log(value):
    text = str(value or "")
    max_bytes = max(4096, int(getattr(Config, "AGENT_MAX_RESULT_LOG_BYTES", 262144)))
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text
    trimmed = raw[:max_bytes].decode("utf-8", errors="replace")
    return f"{trimmed}\n\n[WinHUB] Result log truncated to {max_bytes} bytes."

def ensure_default_groups_and_assign(agent, os_type):
    group_name = f"{os_type} Hosts"
    group = EndpointGroup.query.filter_by(name=group_name).first()
    if not group:
        group = EndpointGroup(name=group_name, description=f"System generated group for {os_type} endpoints")
        db.session.add(group)
        db.session.commit()

    if group not in agent.groups:
        agent.groups.append(group)

def evaluate_and_fire_triggers(agent_id, metric_name, value):
    active_triggers = TriggerRule.query.filter_by(metric_name=metric_name, is_active=True).all()
    if not active_triggers: return

    val_str = str(value).strip().lower()

    for tr in active_triggers:
        thr_str = str(tr.threshold_value).strip().lower()
        is_triggered = False

        if tr.operator == '==': is_triggered = (val_str == thr_str)
        elif tr.operator == '!=': is_triggered = (val_str != thr_str)
        elif tr.operator == 'contains': is_triggered = (thr_str in val_str)
        else:
            try:
                v_num = float(value)
                t_num = float(tr.threshold_value)
                if tr.operator == '>': is_triggered = (v_num > t_num)
                elif tr.operator == '<': is_triggered = (v_num < t_num)
            except:
                pass

        if is_triggered:
            action_tpl = TaskTemplate.query.get(tr.action_template_id)
            if not action_tpl: continue

            try:
                admin_user = User.query.filter_by(is_admin=True).first()
                admin_id = admin_user.id if admin_user else 1

                payload_dict = json.loads(action_tpl.payload) if action_tpl.payload else {}

                WinHubCore.dispatch_task(
                    user_id=admin_id,
                    module_name="Auto-Remediation",
                    action=action_tpl.action_type,
                    target_ids=[agent_id],
                    payload=payload_dict,
                    title=f"[Auto-Fix] {tr.name}"
                )
                log.warning(f"🚨 TRIGGER FIRED: Rule '{tr.name}' matched value '{value}' on host {agent_id}. Firing '{action_tpl.name}'.")
            except Exception as e:
                log.error(f"❌ TRIGGER DISPATCH ERROR: Could not fire action for '{tr.name}': {e}")


@agent_gateway_bp.route('/enroll', methods=['POST'])
def enroll_agent():
    data = request.json or {}
    if not getattr(Config, "AGENT_ENROLLMENT_ENABLED", True):
        return jsonify({"error": "Enrollment Disabled"}), 403
    source_ip = current_client_ip()
    if not enrollment_source_allowed(source_ip):
        return jsonify({"error": "Enrollment Source Denied"}), 403
    if data.get('global_token') != GLOBAL_ENROLLMENT_TOKEN:
        return jsonify({"error": "Auth Failed"}), 401

    hw_id = data.get('hw_id')
    hostname = data.get('hostname', 'Unknown')
    os_type = data.get('os_type', 'Windows')
    network_interfaces = data.get('network_interfaces', [])
    network_info = json.dumps(network_interfaces if isinstance(network_interfaces, list) else [], ensure_ascii=False)
    host_inventory = data.get('host_info', {})
    host_info = json.dumps(host_inventory if isinstance(host_inventory, dict) else {}, ensure_ascii=False)
    agent_version = str(data.get('agent_version') or '').strip()[:50]

    if not hw_id: return jsonify({"error": "Missing Hardware ID"}), 400
    fingerprint = agent_identity_fingerprint(hw_id, hostname, os_type, network_interfaces)
    duplicate_endpoint, duplicate_reasons = find_approved_duplicate_endpoint(hw_id, hostname, source_ip, fingerprint)
    raw_token = f"agt_{secrets.token_urlsafe(32)}"

    agent = Endpoint.query.get(hw_id)
    adopted_identity = False
    if (
        agent
        and getattr(agent, "approval_status", "Pending") != "Approved"
        and duplicate_endpoint
        and should_adopt_duplicate_enrollment(duplicate_reasons)
    ):
        db.session.delete(agent)
        db.session.flush()
        agent = adopt_duplicate_endpoint_identity(
            duplicate_endpoint,
            hw_id,
            raw_token,
            data,
            source_ip,
            fingerprint,
            network_info,
            host_info,
            agent_version,
        )
        adopted_identity = True
    if agent and agent.is_blocked:
        return jsonify({"status": "error", "message": "Blocked"}), 403
    if agent and getattr(agent, "approval_status", "Approved") == "Approved" and not adopted_identity and not getattr(Config, "AGENT_ALLOW_REENROLL_EXISTING", False):
        return jsonify({"status": "error", "message": "Endpoint already enrolled. Delete or reset the endpoint record before re-enrollment."}), 409
    if not agent and duplicate_endpoint and should_adopt_duplicate_enrollment(duplicate_reasons):
        agent = adopt_duplicate_endpoint_identity(
            duplicate_endpoint,
            hw_id,
            raw_token,
            data,
            source_ip,
            fingerprint,
            network_info,
            host_info,
            agent_version,
        )
        adopted_identity = True
    elif not agent:
        agent = Endpoint(id=hw_id, hostname=hostname, auth_token=raw_token,
                         os_version=data.get('os_version'), os_type=os_type, ip_address=source_ip)
        agent.approval_status = "Rejected" if duplicate_endpoint else "Pending"
        agent.first_seen = datetime.utcnow()
        agent.last_enrollment_at = datetime.utcnow()
        agent.last_enrollment_ip = source_ip
        agent.enrollment_attempts = 1
        agent.identity_fingerprint = fingerprint
        agent.agent_version = agent_version
        agent.network_info = network_info
        agent.host_info = host_info
        if duplicate_endpoint:
            agent.identity_warning = (
                "Possible duplicate of approved endpoint "
                f"{duplicate_endpoint.hostname or duplicate_endpoint.id} "
                f"({duplicate_endpoint.id}); matched: {', '.join(duplicate_reasons)}"
            )
        db.session.add(agent)
        db.session.add(RegistrationHistory(
            hw_id=hw_id,
            hostname=hostname,
            ip_address=source_ip,
            event_type="Rejected Duplicate" if duplicate_endpoint else "Pending Approval"
        ))
        db.session.add(ConnectionIpHistory(endpoint_id=hw_id, ip_address=source_ip, source="enrollment"))
    else:
        previous_fingerprint = getattr(agent, "identity_fingerprint", None)
        agent.hostname = hostname
        if source_ip and source_ip != (agent.ip_address or ""):
            db.session.add(ConnectionIpHistory(endpoint_id=agent.id, ip_address=source_ip, source="enrollment"))
            agent.ip_address = source_ip
        agent.last_seen = datetime.utcnow()
        agent.last_enrollment_at = datetime.utcnow()
        agent.last_enrollment_ip = source_ip
        agent.enrollment_attempts = int(agent.enrollment_attempts or 0) + 1
        agent.auth_token = raw_token
        agent.os_version = data.get('os_version', agent.os_version)
        agent.os_type = os_type
        agent.agent_version = agent_version or agent.agent_version
        agent.network_info = network_info
        agent.host_info = host_info
        if not previous_fingerprint:
            agent.identity_fingerprint = fingerprint
        elif previous_fingerprint != fingerprint:
            agent.identity_warning = "Enrollment identity changed. Review hostname, IP and network interfaces before approval."
        if duplicate_endpoint and getattr(agent, "approval_status", "Pending") != "Approved":
            agent.approval_status = "Rejected"
            agent.identity_warning = (
                "Possible duplicate of approved endpoint "
                f"{duplicate_endpoint.hostname or duplicate_endpoint.id} "
                f"({duplicate_endpoint.id}); matched: {', '.join(duplicate_reasons)}"
            )
        if not getattr(agent, "approval_status", None):
            agent.approval_status = "Approved"
        db.session.add(RegistrationHistory(hw_id=hw_id, hostname=hostname, ip_address=source_ip, event_type="Re-enrolled"))

    if getattr(agent, "approval_status", "Approved") == "Approved":
        ensure_default_groups_and_assign(agent, os_type)
    db.session.commit()
    return jsonify({"status": "success", "auth_token": raw_token})

@agent_gateway_bp.route('/poll', methods=['POST'])
def agent_poll():
    data = request.json or {}
    agent = Endpoint.query.get(data.get('hw_id'))

    if not agent or agent.is_blocked or agent.auth_token != data.get('auth_token'):
        return jsonify({"status": "error"}), 403
    if getattr(agent, "approval_status", "Approved") != "Approved":
        source_ip = current_client_ip() or agent.ip_address
        duplicate_endpoint, duplicate_reasons = find_approved_duplicate_endpoint(
            agent.id,
            agent.hostname,
            source_ip,
            getattr(agent, "identity_fingerprint", None),
        )
        if duplicate_endpoint and should_adopt_duplicate_enrollment(duplicate_reasons):
            existing_network_info = agent.network_info or "[]"
            existing_host_info = agent.host_info or "{}"
            pending_hostname = agent.hostname
            pending_os_version = agent.os_version
            pending_os_type = agent.os_type
            pending_fingerprint = getattr(agent, "identity_fingerprint", None)
            db.session.delete(agent)
            db.session.flush()
            agent = adopt_duplicate_endpoint_identity(
                duplicate_endpoint,
                data.get("hw_id"),
                data.get("auth_token"),
                {
                    "hostname": pending_hostname,
                    "os_version": pending_os_version,
                    "os_type": pending_os_type,
                },
                source_ip,
                pending_fingerprint,
                existing_network_info,
                existing_host_info,
                str(data.get("agent_version") or duplicate_endpoint.agent_version or "")[:50],
            )
            db.session.commit()
    if getattr(agent, "approval_status", "Approved") != "Approved":
        agent.last_seen = datetime.utcnow()
        update_agent_connection(agent)
        db.session.commit()
        return jsonify({"status": "pending_approval"}), 200

    now = datetime.utcnow()
    needs_commit = False
    agent_version = str(data.get('agent_version') or '').strip()[:50]
    if update_agent_connection(agent):
        needs_commit = True
    if agent_version and agent_version != (agent.agent_version or ""):
        agent.agent_version = agent_version
        needs_commit = True

    if not agent.last_seen or (now - agent.last_seen).total_seconds() > 60:
        agent.last_seen = now
        needs_commit = True

    task = AgentTask.query.filter_by(endpoint_id=agent.id, status="Pending").order_by(AgentTask.created_at.asc()).first()
    resp = {"status": "idle"}

    if task:
        task.status = "PickedUp"

        # --- БРОНЕБІЙНИЙ ПАРСИНГ PAYLOAD ДЛЯ АГЕНТА ---
        try:
            raw_t = str(task.payload).strip() if task.payload else "{}"
            try:
                # Перша спроба: стандартний JSON
                payload_dict = json.loads(raw_t)
            except Exception:
                # Друга спроба: Python dict string (одинарні лапки)
                import ast
                payload_dict = ast.literal_eval(raw_t)

            if not isinstance(payload_dict, dict):
                payload_dict = {"script": str(raw_t)}
        except Exception:
            payload_dict = {"script": str(task.payload or "")}

        # Гарантія наявності ключа "script", на який очікує агент
        if 'script' not in payload_dict and 'command' in payload_dict:
            payload_dict['script'] = payload_dict['command']

        resp = {
            "status": "task",
            "task_id": task.id,
            "action": task.action_type,
            "payload": payload_dict,
            "timeout_seconds": int(getattr(Config, "AGENT_TASK_TIMEOUT_SECONDS", 1800)),
            "signature": sign_task_message(task.id, task.action_type, payload_dict),
            "signature_alg": "hmac-sha256",
        }
        needs_commit = True

    if needs_commit:
        db.session.commit()

    return jsonify(resp)

@agent_gateway_bp.route('/result', methods=['POST'])
def agent_result():
    data = request.json or {}
    agent = Endpoint.query.get(data.get('hw_id'))

    if not agent or agent.is_blocked or agent.auth_token != data.get('auth_token'):
        return jsonify({"status": "error"}), 403
    update_agent_connection(agent)

    task = AgentTask.query.filter_by(id=data.get('task_id'), endpoint_id=agent.id).first()
    if task:
        log_text = trim_result_log(data.get('log', ''))
        status = data.get('status')
        task.status = status if status in ("Success", "Error", "Cancelled") else "Error"
        task.result_log = log_text
        task.finished_at = datetime.utcnow()

        if task.status == 'Success':
            try:
                # Намагаємося прочитати як JSON, якщо не вийде - як словник (ast)
                raw_p = str(task.payload).strip() if task.payload else "{}"
                try:
                    payload_dict = json.loads(raw_p)
                except:
                    import ast
                    payload_dict = ast.literal_eval(raw_p)

                if isinstance(payload_dict, dict) and payload_dict.get('__is_metric'):
                    metric_name = payload_dict.get('__metric_name', task.title.replace("[Auto] ", ""))
                    val = str(log_text).strip()

                    metric = EndpointMetric.query.filter_by(endpoint_id=agent.id, item_name=metric_name).first()
                    if not metric:
                        metric = EndpointMetric(endpoint_id=agent.id, item_name=metric_name)
                        db.session.add(metric)

                    metric.last_value = val
                    metric.last_updated = datetime.utcnow()

                    evaluate_and_fire_triggers(agent.id, metric_name, val)

            except Exception as e:
                log.error(f"Error processing metric result: {e}")

        db.session.commit()

        pending_tasks = AgentTask.query.filter(
            AgentTask.job_id == task.job_id,
            AgentTask.status.in_(['Pending', 'PickedUp', 'Running'])
        ).count()

        if pending_tasks == 0:
            WinHubCore.process_job_completion(task.job_id)

        return jsonify({"status": "success"})

    return jsonify({"status": "error"}), 404

@agent_gateway_bp.route('/telemetry', methods=['POST'])
def agent_telemetry():
    data = request.json or {}
    agent = Endpoint.query.get(data.get('hw_id'))

    if not agent or agent.is_blocked or agent.auth_token != data.get('auth_token'):
        return jsonify({"status": "error"}), 403

    agent_version = str(data.get('agent_version') or '').strip()[:50]
    if agent_version:
        agent.agent_version = agent_version
    host_inventory = data.get('host_info')
    if isinstance(host_inventory, dict):
        agent.host_info = json.dumps(host_inventory, ensure_ascii=False)
    update_agent_connection(agent)

    telemetry = TelemetryHistory(
        endpoint_id=agent.id,
        cpu_usage=data.get('cpu', 0.0),
        ram_usage=data.get('ram', 0.0),
        disk_c_free=data.get('disk_c', 0.0)
    )

    agent.last_seen = datetime.utcnow()
    db.session.add(telemetry)
    db.session.commit()

    return jsonify({"status": "success"})
