"""Immutable report revisions and delivery audit snapshots."""

import hashlib
import json
from datetime import datetime

from sqlalchemy import func

from core.database import db, ReportDelivery, ReportRevision


def report_content_hash(content):
    return hashlib.sha256(str(content or "").encode("utf-8")).hexdigest()


def latest_report_revision(report_id):
    return ReportRevision.query.filter_by(report_id=str(report_id)).order_by(
        ReportRevision.revision_number.desc()
    ).first()


def create_report_revision(
    report,
    content,
    *,
    kind="edited",
    actor_user_id=None,
    actor_name=None,
    reason=None,
    allow_same=False,
):
    """Create an immutable revision and make it the current working body."""
    content = str(content or "")
    digest = report_content_hash(content)
    latest = latest_report_revision(report.id)
    if latest and latest.content_hash == digest and not allow_same:
        report.report_data = content
        report.current_revision_number = latest.revision_number
        return latest

    current_number = db.session.query(func.max(ReportRevision.revision_number)).filter(
        ReportRevision.report_id == str(report.id)
    ).scalar() or 0
    revision_number = int(current_number) + 1
    revision = ReportRevision(
        report_id=str(report.id),
        revision_number=revision_number,
        kind=str(kind or "edited")[:30],
        content=content,
        content_hash=digest,
        actor_user_id=actor_user_id,
        actor_name=(str(actor_name)[:150] if actor_name else None),
        reason=(str(reason)[:500] if reason else None),
    )
    db.session.add(revision)
    report.report_data = content
    report.current_revision_number = revision_number
    if not report.original_content_hash:
        report.original_content_hash = digest
    db.session.flush()

    from core.history_search import replace_search_field

    replace_search_field("report", str(report.id), "current", content)
    if revision_number == 1:
        replace_search_field("report", str(report.id), "original", content)
    revision_bodies = [row[0] for row in db.session.query(ReportRevision.content).filter(
        ReportRevision.report_id == str(report.id)
    ).order_by(ReportRevision.revision_number).all()]
    replace_search_field("report", str(report.id), "revisions", "\n".join(revision_bodies))
    return revision


def ensure_report_revision(report, *, actor_user_id=None, actor_name=None):
    latest = latest_report_revision(report.id)
    digest = report_content_hash(report.report_data)
    if latest and latest.content_hash == digest:
        if not report.current_revision_number:
            report.current_revision_number = latest.revision_number
        return latest
    return create_report_revision(
        report,
        report.report_data or "",
        kind="recovered" if latest is None else "edited",
        actor_user_id=actor_user_id,
        actor_name=actor_name,
        reason="Imported from the current report body" if latest is None else "Captured before delivery",
    )


def record_report_delivery(
    report,
    *,
    channel,
    destination,
    subject=None,
    note=None,
    content_snapshot=None,
    actor_user_id=None,
    actor_name=None,
    status="Pending",
    result_details=None,
):
    revision = ensure_report_revision(
        report,
        actor_user_id=actor_user_id,
        actor_name=actor_name,
    )
    sent_content = revision.content if content_snapshot is None else str(content_snapshot or "")
    delivery = ReportDelivery(
        report_id=str(report.id),
        revision_id=revision.id,
        channel=str(channel or "unknown")[:30],
        destination=json.dumps(destination, ensure_ascii=False)
        if isinstance(destination, (dict, list))
        else str(destination or ""),
        subject=(str(subject)[:255] if subject else None),
        note=str(note or ""),
        content_snapshot=sent_content,
        content_hash=report_content_hash(sent_content),
        actor_user_id=actor_user_id,
        actor_name=(str(actor_name)[:150] if actor_name else None),
        status=str(status or "Pending")[:30],
        result_details=json.dumps(result_details, ensure_ascii=False)
        if isinstance(result_details, (dict, list))
        else str(result_details or ""),
    )
    if delivery.status not in {"Pending", "Sending"}:
        delivery.completed_at = datetime.utcnow()
    db.session.add(delivery)
    db.session.flush()
    from core.history_search import replace_search_field
    delivery_bodies = [row[0] for row in db.session.query(ReportDelivery.content_snapshot).filter(
        ReportDelivery.report_id == str(report.id)
    ).order_by(ReportDelivery.created_at).all()]
    replace_search_field("report", str(report.id), "deliveries", "\n".join(delivery_bodies))
    return delivery, revision


def finish_report_delivery(delivery, *, success, details=None):
    delivery.status = "Success" if success else "Error"
    if details is not None:
        delivery.result_details = (
            json.dumps(details, ensure_ascii=False)
            if isinstance(details, (dict, list))
            else str(details)
        )
    delivery.completed_at = datetime.utcnow()
    return delivery
