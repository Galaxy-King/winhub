import html
import json
import uuid
from typing import List
from flask import g, has_request_context, request, session
from sqlalchemy.exc import PendingRollbackError
from core.database import db, User, Endpoint, EndpointGroup, AgentTask, TaskTemplate, AuditLog
from core.security import sec_manager
from core.permissions import request_api_group_scope
from core.report_renderer_client import render_report_template
from core.template_security import template_approval_valid

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

        report_template_id = payload.get("__report_template_id") if isinstance(payload, dict) else None
        if report_template_id:
            report_template = TaskTemplate.query.get(str(report_template_id))
            if not report_template or getattr(report_template, "type", "action") != "report" or not template_approval_valid(report_template):
                raise PermissionError("Approved report template not found or approval seal is invalid")

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
    def process_job_completion(job_id: str, app=None, include_statuses=None, force=False):
        """Збирає результати і формує звіт (з використанням кастомного шаблону, якщо він заданий)"""
        import json
        import re
        from core.database import AgentTask, AggregatedJob, TaskTemplate, db

        def result_log_summary(value, limit=260):
            text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
            if not text:
                return "No output"
            return text[: limit - 3] + "..." if len(text) > limit else text

        def report_looks_html(value):
            probe = (value or "").lstrip().lower()[:1000]
            return probe.startswith("<") or any(tag in probe for tag in ("<html", "<body", "<h1", "<table", "<div"))

        def build_ignored_banner(ignored_results, html_mode=False):
            if not ignored_results:
                return ""
            if html_mode:
                items = "\n".join(
                    "<li><strong>{host}</strong> - {status}: {reason}</li>".format(
                        host=html.escape(str(item.get("host") or "Unknown")),
                        status=html.escape(str(item.get("status") or "Ignored")),
                        reason=html.escape(result_log_summary(item.get("log"))),
                    )
                    for item in ignored_results
                )
                return (
                    '<div style="border:1px solid #f59e0b;background:#451a03;color:#fffbeb;'
                    'padding:12px 14px;margin:0 0 18px 0;border-radius:10px;">'
                    '<h2 style="margin:0 0 8px 0;color:#fde68a;font-size:18px;">'
                    "Failed endpoints</h2>"
                    '<p style="margin:0 0 8px 0;">The following endpoints did not complete successfully. '
                    "They were not included in success-only report sections.</p>"
                    f'<ul style="margin:0;padding-left:20px;">{items}</ul>'
                    "</div>\n"
                )
            lines = [
                "FAILED ENDPOINTS",
                "The following endpoints did not complete successfully. "
                "They were not included in success-only report sections.",
            ]
            for item in ignored_results:
                lines.append(
                    f"- {item.get('host') or 'Unknown'} - {item.get('status') or 'Ignored'}: "
                    f"{result_log_summary(item.get('log'))}"
                )
            return "\n".join(lines) + "\n\n"

        def prepend_ignored_banner(report_text, ignored_results):
            if not ignored_results:
                return report_text
            if "FAILED ENDPOINT DETAILS" in str(report_text or "").upper():
                return report_text
            html_mode = report_looks_html(report_text)
            return build_ignored_banner(ignored_results, html_mode=html_mode) + (report_text or "")

        try:
            split_prefix = f"{uuid.UUID(job_id).hex}.%"
        except Exception:
            split_prefix = None

        existing_split = split_prefix and AggregatedJob.query.filter(AggregatedJob.id.like(split_prefix)).first()
        if (AggregatedJob.query.get(job_id) or existing_split) and not force:
            return
        if force:
            AggregatedJob.query.filter_by(id=job_id).delete(synchronize_session=False)
            if split_prefix:
                AggregatedJob.query.filter(AggregatedJob.id.like(split_prefix)).delete(synchronize_session=False)

        tasks = AgentTask.query.filter_by(job_id=job_id).all()
        if not tasks: return
        if include_statuses:
            allowed_statuses = {str(item).lower() for item in include_statuses}
            tasks = [task for task in tasks if str(task.status or "Pending").lower() in allowed_statuses]
        if not tasks:
            return

        total = len(tasks)
        success = sum(1 for t in tasks if t.status == 'Success')
        errors = total - success

        # Спробуємо знайти report_template_id в payload першої таски
        report_template_id = None
        try:
            first_payload = json.loads(tasks[0].payload)
            report_template_id = first_payload.get('__report_template_id')
        except: pass

        # Збираємо структуровані дані від агентів. Custom report templates receive
        # only successful endpoints in `results`; failed/timed-out endpoints are
        # exposed separately and are summarized at the top of the final report.
        all_results_data = []
        successful_results_data = []
        ignored_results_data = []
        for t in tasks:
            host = t.endpoint.hostname if t.endpoint else "Unknown"
            parsed_data = {}
            try:
                parsed_data = json.loads(t.result_log)
                if isinstance(parsed_data, dict):
                    log_text = str(
                        parsed_data.get("error")
                        or parsed_data.get("message")
                        or "Structured JSON result"
                    )
                else:
                    log_text = result_log_summary(parsed_data)
            except:
                log_text = t.result_log.strip() if t.result_log else "No output"

            item = {
                "host": host,
                "status": t.status,
                "data": parsed_data,
                "log": log_text
            }
            all_results_data.append(item)
            if t.status == "Success":
                successful_results_data.append(item)
            else:
                ignored_results_data.append(item)

        report_summary = {
            "total": total,
            "success": success,
            "errors": errors,
            "ignored": len(ignored_results_data),
            "included": len(successful_results_data),
            "job_id": job_id,
            "job_title": tasks[0].title,
        }

        final_report_text = ""

        # Якщо є кастомний шаблон звіту — рендеримо через Jinja2
        if report_template_id:
            tpl = TaskTemplate.query.get(report_template_id)
            if tpl and getattr(tpl, "type", "action") == "report" and template_approval_valid(tpl) and tpl.payload:
                try:
                    # В payload шаблону звіту лежить сам текст листа
                    template_string = json.loads(tpl.payload).get('script', '')
                    # Рендеримо. `results` contains successful endpoints only; failed
                    # endpoints are available as `ignored_results` / `failed_results`.
                    final_report_text = render_report_template(
                        template_string,
                        {
                            "results": successful_results_data,
                            "all_results": all_results_data,
                            "ignored_results": ignored_results_data,
                            "failed_results": ignored_results_data,
                            "summary": report_summary,
                            "job_title": tasks[0].title,
                        },
                    )
                except Exception as e:
                    final_report_text = f"Помилка рендерингу звіту: {str(e)}\n\n"

        # Якщо шаблону немає або була помилка — формуємо стандартний список
        if not final_report_text:
            report_lines = []
            for r in successful_results_data:
                status_icon = "✅" if r['status'] == 'Success' else "❌"
                if r['data'] and 'password' in r['data']:
                    details = f"User: {r['data'].get('username')} | Pass: {r['data'].get('password')}"
                else:
                    details = json.dumps(r['data']) if r['data'] else r['log']
                report_lines.append(f"{status_icon} [{r['host']}] - {details}")
            final_report_text = "\n".join(report_lines)

        split_pattern = re.compile(
            r'\[\[WINHUB_REPORT(?:\s+title="([^"]*)")?\]\]\s*(.*?)\s*\[\[/WINHUB_REPORT\]\]',
            re.DOTALL
        )
        split_reports = [
            {
                "title": (match.group(1) or tasks[0].title or "Untitled Job").strip(),
                "body": (match.group(2) or "").strip()
            }
            for match in split_pattern.finditer(final_report_text or "")
            if (match.group(2) or "").strip()
        ]

        if split_reports:
            parent_hex = uuid.UUID(job_id).hex
            for index, report in enumerate(split_reports[:999], start=1):
                db.session.add(AggregatedJob(
                    id=f"{parent_hex}.{index:03d}",
                    title=report["title"][:150],
                    total_count=total,
                    success_count=success,
                    error_count=errors,
                    report_data=prepend_ignored_banner(report["body"], ignored_results_data),
                    status="Waiting Review"
                ))
        else:
            final_report_text = prepend_ignored_banner(final_report_text, ignored_results_data)
            db.session.add(AggregatedJob(
                id=job_id,
                title=tasks[0].title or "Untitled Job",
                total_count=total,
                success_count=success,
                error_count=errors,
                report_data=final_report_text,
                status="Waiting Review"
            ))
        db.session.commit()
