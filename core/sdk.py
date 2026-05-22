import json
import uuid
from typing import List
from flask import g, has_request_context, request, session, render_template_string
from sqlalchemy.exc import PendingRollbackError
from core.database import db, User, Endpoint, EndpointGroup, AgentTask, TaskTemplate, AuditLog
from core.security import sec_manager
from core.permissions import request_api_group_scope

class WinHubCore:
    @staticmethod
    def audit(
        user_id=None,
        username=None,
        module=None,
        action=None,
        details=None,
        status="Success",
        actor_type=None,
        target_type=None,
        target_id=None,
        ip_address=None,
        request_id=None
    ):
        if not username and user_id:
            try:
                user = User.query.get(user_id)
            except PendingRollbackError:
                db.session.rollback()
                user = User.query.get(user_id)
            username = user.username if user else None
        if has_request_context():
            username = username or session.get("username")
            actor_type = actor_type or ("api_key" if session.get("api_key_auth") else "user")
            if actor_type == "api_key" and session.get("api_key_id"):
                username = f"{username or 'API Key'} (key:{session.get('api_key_id')})"
            ip_address = ip_address or request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
            request_id = request_id or getattr(g, "request_id", None)
        else:
            actor_type = actor_type or "system"

        if isinstance(details, (dict, list)):
            details = json.dumps(details, ensure_ascii=False)

        if module and action:
            audit_action = f"{module}: {action}"
        else:
            audit_action = action or module or "Audit Event"

        entry = AuditLog(
            user=username or "System",
            actor_type=actor_type or "system",
            actor_name=username or "System",
            module=module,
            action=audit_action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            ip_address=ip_address,
            request_id=request_id,
            details=details or "",
            status=status
        )
        try:
            db.session.add(entry)
            db.session.commit()
        except PendingRollbackError:
            db.session.rollback()
            db.session.add(entry)
            db.session.commit()
        return entry
    
    @staticmethod
    def get_allowed_hosts(user_id: int) -> List[Endpoint]:
        user = User.query.get(user_id)
        if not user: return []
        api_group_ids = request_api_group_scope()
        if api_group_ids is not None:
            if not api_group_ids:
                return []
            return Endpoint.query.join(Endpoint.groups).filter(
                EndpointGroup.id.in_(api_group_ids),
                Endpoint.approval_status == "Approved"
            ).distinct().all()
        if user.is_admin: return Endpoint.query.all()
        
        allowed_hosts = set()
        for group in user.allowed_host_groups:
            for host in group.endpoints:
                if getattr(host, "approval_status", "Approved") == "Approved":
                    allowed_hosts.add(host)
        return list(allowed_hosts)

    @staticmethod
    def get_allowed_groups(user_id: int) -> List[EndpointGroup]:
        user = User.query.get(user_id)
        if not user: return []
        api_group_ids = request_api_group_scope()
        if api_group_ids is not None:
            if not api_group_ids:
                return []
            return EndpointGroup.query.filter(EndpointGroup.id.in_(api_group_ids)).order_by(EndpointGroup.name).all()
        if user.is_admin: return EndpointGroup.query.all()
        return list(user.allowed_host_groups)

    @staticmethod
    def can_manage_host(user_id: int, host_id: str) -> bool:
        user = User.query.get(user_id)
        if not user: return False
        host = Endpoint.query.get(host_id)
        if not host: return False
        api_group_ids = request_api_group_scope()
        if api_group_ids is not None:
            if not api_group_ids:
                return False
            return getattr(host, "approval_status", "Approved") == "Approved" and any(group.id in api_group_ids for group in host.groups)
        if user.is_admin: return True
        if getattr(host, "approval_status", "Approved") != "Approved":
            return False
        for group in user.allowed_host_groups:
            if host in group.endpoints: return True
        return False

    @staticmethod
    def dispatch_task(user_id: int, module_name: str, action: str, target_ids: list, payload: dict, title: str = "Automated Task") -> str:
        user = User.query.get(user_id)
        if not user: raise PermissionError("Invalid user")

        payload_json = json.dumps(payload)
        job_id = str(uuid.uuid4())

        requested_ids = list(dict.fromkeys(str(hid) for hid in target_ids if hid))
        allowed_ids = {
            host.id
            for host in WinHubCore.get_allowed_hosts(user_id)
            if getattr(host, "approval_status", "Approved") == "Approved"
        }

        tasks = [
            AgentTask(
                job_id=job_id,
                endpoint_id=hid,
                title=title,
                module_source=module_name,
                action_type=action,
                payload=payload_json,
                created_by=user.username
            )
            for hid in requested_ids
            if hid in allowed_ids
        ]

        if tasks:
            db.session.add_all(tasks)
            db.session.commit()
            return job_id
        else:
            raise PermissionError("No authorized targets selected")

    @staticmethod
    def process_job_completion(job_id: str, app=None):
        """Збирає результати і формує звіт (з використанням кастомного шаблону, якщо він заданий)"""
        import json
        from core.database import AgentTask, AggregatedJob, TaskTemplate, db
        from flask import render_template_string
        
        if AggregatedJob.query.get(job_id):
            return
            
        tasks = AgentTask.query.filter_by(job_id=job_id).all()
        if not tasks: return

        total = len(tasks)
        success = sum(1 for t in tasks if t.status == 'Success')
        errors = total - success
        
        # Спробуємо знайти report_template_id в payload першої таски
        report_template_id = None
        try:
            first_payload = json.loads(tasks[0].payload)
            report_template_id = first_payload.get('__report_template_id')
        except: pass

        # Збираємо структуровані дані від усіх агентів
        results_data = []
        for t in tasks:
            host = t.endpoint.hostname if t.endpoint else "Unknown"
            parsed_data = {}
            try:
                parsed_data = json.loads(t.result_log)
                log_text = "JSON Object"
            except:
                log_text = t.result_log.strip() if t.result_log else "No output"
            
            results_data.append({
                "host": host,
                "status": t.status,
                "data": parsed_data,
                "log": log_text
            })

        final_report_text = ""

        # Якщо є кастомний шаблон звіту — рендеримо через Jinja2
        if report_template_id:
            tpl = TaskTemplate.query.get(report_template_id)
            if tpl and tpl.payload:
                try:
                    # В payload шаблону звіту лежить сам текст листа
                    template_string = json.loads(tpl.payload).get('script', '')
                    # Рендеримо! Передаємо масив results всередину шаблону
                    final_report_text = render_template_string(template_string, results=results_data, job_title=tasks[0].title)
                except Exception as e:
                    final_report_text = f"Помилка рендерингу звіту: {str(e)}\n\n"
        
        # Якщо шаблону немає або була помилка — формуємо стандартний список
        if not final_report_text:
            report_lines = []
            for r in results_data:
                status_icon = "✅" if r['status'] == 'Success' else "❌"
                if r['data'] and 'password' in r['data']:
                    details = f"User: {r['data'].get('username')} | Pass: {r['data'].get('password')}"
                else:
                    details = json.dumps(r['data']) if r['data'] else r['log']
                report_lines.append(f"{status_icon} [{r['host']}] - {details}")
            final_report_text = "\n".join(report_lines)

        agg_job = AggregatedJob(
            id=job_id,
            title=tasks[0].title or "Untitled Job",
            total_count=total,
            success_count=success,
            error_count=errors,
            report_data=final_report_text,
            status="Waiting Review"
        )
        db.session.add(agg_job)
        db.session.commit()
