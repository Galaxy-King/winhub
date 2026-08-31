import html
import hashlib
import json
import uuid
from typing import List
from flask import g, has_request_context, request, session
from sqlalchemy.exc import PendingRollbackError
from core.database import db, User, Endpoint, EndpointGroup, AgentTask, TaskTemplate, AuditLog
from core.security import sec_manager
from core.permissions import has_permission, request_api_group_scope
from core.group_access import allowed_group_ids_for_action, allowed_host_ids_for_action
from core.report_renderer_client import render_report_template
from core.template_security import template_approval_valid

class WinHubCore:
    @staticmethod
    def request_user(user_id):
        cached_user = getattr(g, "infrastructure_current_user", None) if has_request_context() else None
        return cached_user if getattr(cached_user, "id", None) == user_id else User.query.get(user_id)

    @staticmethod
    def audit(
        user_id=None,
        username=None,
        module=None,
        action=None,
        details=None,
        status="Success",
        actor_type=None,
        source_type=None,
        target_type=None,
        target_id=None,
        ip_address=None,
        request_id=None
    ):
        actor_user = None
        if user_id:
            try:
                actor_user = WinHubCore.request_user(user_id)
            except PendingRollbackError:
                db.session.rollback()
                actor_user = WinHubCore.request_user(user_id)
            username = username or (actor_user.username if actor_user else None)
        if has_request_context():
            if actor_user is None and session.get("user_id"):
                actor_user = WinHubCore.request_user(session.get("user_id"))
                user_id = getattr(actor_user, "id", None)
            username = username or session.get("username")
            actor_type = actor_type or ("api_key" if session.get("api_key_auth") else "user")
            source_type = source_type or ("api" if session.get("api_key_auth") else "web")
            if actor_type == "api_key" and session.get("api_key_id"):
                username = f"{username or 'API Key'} (key:{session.get('api_key_id')})"
            if not ip_address:
                from core.api_access import effective_client_ip
                ip_address = effective_client_ip(request)
            request_id = request_id or getattr(g, "request_id", None)
        else:
            actor_type = actor_type or "system"
            source_type = source_type or "system"

        if isinstance(details, (dict, list)):
            details = json.dumps(details, ensure_ascii=False)

        if module and action:
            audit_action = f"{module}: {action}"
        else:
            audit_action = action or module or "Audit Event"

        audit_session_id = session.get("audit_session_id") if has_request_context() else None
        session_id_hash = (
            hashlib.sha256(str(audit_session_id).encode("utf-8")).hexdigest()
            if audit_session_id else None
        )
        actor_role = "superadmin" if getattr(actor_user, "is_admin", False) else (
            "api_key" if actor_type == "api_key" else "operator" if actor_user else "system"
        )
        entry = AuditLog(
            user=username or "System",
            actor_user_id=getattr(actor_user, "id", None),
            actor_type=actor_type or "system",
            actor_name=username or "System",
            actor_role=actor_role,
            source_type=source_type,
            session_id_hash=session_id_hash,
            user_agent=request.headers.get("User-Agent", "")[:1000] if has_request_context() else None,
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
            db.session.flush()
            from core.history_search import index_audit_log
            index_audit_log(entry)
            db.session.commit()
        except PendingRollbackError:
            db.session.rollback()
            db.session.add(entry)
            db.session.flush()
            db.session.commit()
        return entry

    @staticmethod
    def get_allowed_hosts(user_id: int, action_id: str = "view_hosts") -> List[Endpoint]:
        user = WinHubCore.request_user(user_id)
        if not user or not has_permission(user, "Infrastructure", action_id):
            return []
        approved_only = not (user.is_admin and request_api_group_scope() is None)
        host_ids = allowed_host_ids_for_action(user, action_id, approved_only=approved_only)
        if not host_ids:
            return []
        return Endpoint.query.filter(Endpoint.id.in_(host_ids)).all()

    @staticmethod
    def get_allowed_groups(user_id: int, action_id: str = "view_groups") -> List[EndpointGroup]:
        user = WinHubCore.request_user(user_id)
        if not user or not has_permission(user, "Infrastructure", action_id):
            return []
        group_ids = allowed_group_ids_for_action(user, action_id)
        if not group_ids:
            return []
        return EndpointGroup.query.filter(EndpointGroup.id.in_(group_ids)).order_by(EndpointGroup.name).all()

    @staticmethod
    def can_manage_host(user_id: int, host_id: str, action_id: str = "view_hosts") -> bool:
        user = WinHubCore.request_user(user_id)
        return bool(
            user
            and has_permission(user, "Infrastructure", action_id)
            and str(host_id) in allowed_host_ids_for_action(
                user,
                action_id,
                approved_only=not (user.is_admin and request_api_group_scope() is None),
            )
        )

    @staticmethod
    def authorized_target_ids(user_id: int, target_ids, action_id: str = "run_tasks") -> set:
        """Resolve a target batch with one scoped query instead of N host checks."""
        user = WinHubCore.request_user(user_id)
        if not user or not has_permission(user, "Infrastructure", action_id):
            return set()
        requested_ids = list(dict.fromkeys(str(item) for item in (target_ids or []) if item))
        if not requested_ids:
            return set()

        query = db.session.query(Endpoint.id).filter(
            Endpoint.id.in_(requested_ids),
            Endpoint.approval_status == "Approved",
        )
        group_ids = allowed_group_ids_for_action(user, action_id)
        if not group_ids and not (user.is_admin and request_api_group_scope() is None):
            return set()
        if not (user.is_admin and request_api_group_scope() is None):
            query = query.join(Endpoint.groups).filter(EndpointGroup.id.in_(group_ids)).distinct()
        return {row[0] for row in query.all()}

    @staticmethod
    def dispatch_task(
        user_id: int,
        module_name: str,
        action: str,
        target_ids: list,
        payload: dict,
        title: str = "Automated Task",
        *,
        source_type=None,
        actor_name=None,
        actor_user_id=None,
        system_actor=False,
    ) -> str:
        user = WinHubCore.request_user(user_id)
        if not user: raise PermissionError("Invalid user")

        report_template_id = payload.get("__report_template_id") if isinstance(payload, dict) else None
        if report_template_id:
            report_template = TaskTemplate.query.get(str(report_template_id))
            if not report_template or getattr(report_template, "type", "action") != "report" or not template_approval_valid(report_template):
                raise PermissionError("Approved report template not found or approval seal is invalid")

        payload_json = json.dumps(payload)
        job_id = str(uuid.uuid4())

        requested_ids = list(dict.fromkeys(str(hid) for hid in target_ids if hid))
        allowed_ids = WinHubCore.authorized_target_ids(user_id, requested_ids)

        hosts_by_id = {
            host.id: host
            for host in Endpoint.query.filter(Endpoint.id.in_(requested_ids)).all()
        }
        resolved_source = str(source_type or "").strip().lower()
        if not resolved_source:
            if has_request_context() and session.get("api_key_auth"):
                resolved_source = "api"
            elif str(module_name or "").lower() == "scheduler" or str(title or "").startswith("[Auto]"):
                resolved_source = "scheduler"
            elif str(title or "").startswith("[Auto-Fix]"):
                resolved_source = "trigger"
            else:
                resolved_source = "manual"
        template_id = payload.get("__template_id") or payload.get("__report_template_id") if isinstance(payload, dict) else None
        schedule_id = payload.get("__schedule_id") if isinstance(payload, dict) else None

        tasks = [
            AgentTask(
                job_id=job_id,
                endpoint_id=hid,
                endpoint_id_snapshot=hid,
                endpoint_hostname_snapshot=getattr(hosts_by_id.get(hid), "hostname", None),
                endpoint_name_snapshot=getattr(hosts_by_id.get(hid), "display_name", None),
                endpoint_groups_snapshot=json.dumps([
                    {"id": group.id, "name": group.name}
                    for group in getattr(hosts_by_id.get(hid), "groups", [])
                ], ensure_ascii=False),
                title=title,
                module_source=module_name,
                action_type=action,
                source_type=resolved_source,
                actor_user_id=None if system_actor else (actor_user_id or user.id),
                template_id=str(template_id) if template_id else None,
                schedule_id=str(schedule_id) if schedule_id else None,
                payload=payload_json,
                created_by=actor_name or user.username
            )
            for hid in requested_ids
            if hid in allowed_ids
        ]

        if tasks:
            db.session.add_all(tasks)
            db.session.flush()
            from core.history_search import index_agent_task
            for task in tasks:
                index_agent_task(task)
            db.session.commit()
            WinHubCore.audit(
                user_id=None if system_actor else (actor_user_id or user.id),
                username=actor_name or user.username,
                module=module_name or "Infrastructure",
                action="Task Dispatched",
                details={
                    "job_id": job_id,
                    "title": title,
                    "action_type": action,
                    "target_count": len(tasks),
                    "template_id": template_id,
                    "schedule_id": schedule_id,
                },
                target_type="task_job",
                target_id=job_id,
                source_type=resolved_source,
                status="Success",
            )
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

        existing_reports = AggregatedJob.query.filter_by(id=job_id).all()
        if split_prefix:
            existing_reports.extend(
                AggregatedJob.query.filter(AggregatedJob.id.like(split_prefix)).all()
            )
        existing_reports = list({row.id: row for row in existing_reports}.values())
        if existing_reports and not force:
            return
        if existing_reports:
            from core.report_versions import ensure_report_revision
            for existing_report in existing_reports:
                ensure_report_revision(
                    existing_report,
                    actor_user_id=getattr(existing_report, "actor_user_id", None),
                    actor_name=getattr(existing_report, "created_by", None) or "System",
                )
            db.session.flush()

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
            host = t.endpoint.hostname if t.endpoint else (
                t.endpoint_name_snapshot or t.endpoint_hostname_snapshot or t.endpoint_id_snapshot or "Deleted host"
            )
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

        created_reports = []
        report_versions = []

        def upsert_generated_report(report_id, title, body):
            report_row = AggregatedJob.query.get(report_id)
            kind = "regenerated" if report_row else "generated"
            if report_row is None:
                report_row = AggregatedJob(id=report_id)
                db.session.add(report_row)
            report_row.title = (title or "Untitled Job")[:150]
            report_row.total_count = total
            report_row.success_count = success
            report_row.error_count = errors
            report_row.status = "Waiting Review"
            report_row.actor_user_id = getattr(tasks[0], "actor_user_id", None)
            report_row.created_by = tasks[0].created_by
            report_row.source_type = getattr(tasks[0], "source_type", None)
            report_row.template_id = getattr(tasks[0], "template_id", None)
            created_reports.append(report_row)
            report_versions.append((report_row, body, kind))
            return report_row

        if split_reports:
            parent_hex = uuid.UUID(job_id).hex
            for index, report in enumerate(split_reports[:999], start=1):
                upsert_generated_report(
                    f"{parent_hex}.{index:03d}",
                    report["title"],
                    prepend_ignored_banner(report["body"], ignored_results_data),
                )
        else:
            final_report_text = prepend_ignored_banner(final_report_text, ignored_results_data)
            upsert_generated_report(job_id, tasks[0].title, final_report_text)

        generated_ids = {row.id for row in created_reports}
        for old_report in existing_reports:
            if old_report.id not in generated_ids:
                old_report.status = "Superseded"

        db.session.flush()
        from core.report_versions import create_report_revision
        for report_row, report_body, revision_kind in report_versions:
            create_report_revision(
                report_row,
                report_body or "",
                kind=revision_kind,
                actor_user_id=getattr(tasks[0], "actor_user_id", None),
                actor_name=tasks[0].created_by,
                reason="Generated from endpoint results" if revision_kind == "generated" else "Regenerated from updated endpoint results",
            )
        db.session.commit()
        for report_row in created_reports:
            WinHubCore.audit(
                user_id=getattr(tasks[0], "actor_user_id", None),
                username=tasks[0].created_by,
                module="Infrastructure",
                action="Report Generated",
                details={
                    "job_id": job_id,
                    "report_id": report_row.id,
                    "title": report_row.title,
                    "total": total,
                    "success": success,
                    "errors": errors,
                },
                target_type="report",
                target_id=report_row.id,
                source_type=getattr(tasks[0], "source_type", None) or "system",
                status="Success",
            )
