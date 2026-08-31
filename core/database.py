from flask_sqlalchemy import SQLAlchemy
import sqlalchemy.types as types
from datetime import datetime
import uuid
from core.security import sec_manager

db = SQLAlchemy()

# --- ШИФРУВАННЯ ---
class EncryptedText(types.TypeDecorator):
    impl = types.Text
    cache_ok = True
    def process_bind_param(self, value, dialect):
        return sec_manager.encrypt_payload(str(value)) if value else value
    def process_result_value(self, value, dialect):
        return sec_manager.decrypt_payload(value) if value else value

class EncryptedString(types.TypeDecorator):
    impl = types.Text
    cache_ok = True
    def process_bind_param(self, value, dialect):
        return sec_manager.encrypt_payload(str(value)) if value else value
    def process_result_value(self, value, dialect):
        return sec_manager.decrypt_payload(value) if value else value

# --- ЗВ'ЯЗКИ ---
user_group_m2m = db.Table('user_group_access',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), primary_key=True),
    db.Column('group_id', db.String(36), db.ForeignKey('endpoint_groups.id', ondelete="CASCADE"), primary_key=True),
    db.Column('permissions', db.Text, nullable=False, server_default='["*"]')
)

api_key_group_m2m = db.Table('api_key_group_access',
    db.Column('api_key_id', db.Integer, db.ForeignKey('api_keys.id', ondelete="CASCADE"), primary_key=True),
    db.Column('group_id', db.String(36), db.ForeignKey('endpoint_groups.id', ondelete="CASCADE"), primary_key=True),
    db.Column('permissions', db.Text, nullable=False, server_default='[]')
)

api_key_template_m2m = db.Table('api_key_template_access',
    db.Column('api_key_id', db.Integer, db.ForeignKey('api_keys.id', ondelete="CASCADE"), primary_key=True),
    db.Column('template_id', db.String(36), db.ForeignKey('task_templates.id', ondelete="CASCADE"), primary_key=True)
)

endpoint_group_m2m = db.Table('endpoint_group_membership',
    db.Column('endpoint_id', db.String(100), db.ForeignKey('endpoints.id', ondelete="CASCADE"), primary_key=True),
    db.Column('group_id', db.String(36), db.ForeignKey('endpoint_groups.id', ondelete="CASCADE"), primary_key=True)
)

# --- МОДЕЛІ ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(256))
    totp_secret = db.Column(EncryptedString)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    force_2fa_setup = db.Column(db.Boolean, default=True)
    allowed_modules = db.Column(db.Text, default="[]")
    allowed_host_groups = db.relationship('EndpointGroup', secondary=user_group_m2m, backref='allowed_users', lazy='dynamic')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('Task', backref='user', lazy=True)
    reset_tokens = db.relationship('PasswordReset', backref='user', cascade="all, delete-orphan")

class PasswordReset(db.Model):
    __tablename__ = 'password_resets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False, unique=True)
    code = db.Column(db.String(10), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    attempts = db.Column(db.Integer, default=0)

class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(256), unique=True, nullable=False)
    prefix = db.Column(db.String(10), nullable=False)
    permissions = db.Column(db.Text, default="[]")
    allowed_networks = db.Column(db.Text, default="[]")
    ip_allowlist_enforced = db.Column(db.Boolean, default=True, nullable=False)
    template_scope_enforced = db.Column(db.Boolean, default=True, nullable=False)
    max_targets_per_run = db.Column(db.Integer, default=1, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    last_used_ip = db.Column(EncryptedString, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref=db.backref('api_keys', cascade="all, delete-orphan"))

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user = db.Column(db.String(100))
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True, index=True)
    actor_type = db.Column(db.String(20), default="user", index=True)
    actor_name = db.Column(db.String(150), index=True)
    actor_role = db.Column(db.String(30), nullable=True, index=True)
    source_type = db.Column(db.String(30), nullable=True, index=True)
    session_id_hash = db.Column(db.String(64), nullable=True, index=True)
    user_agent = db.Column(EncryptedText)
    module = db.Column(db.String(80), index=True)
    action = db.Column(db.String(100), index=True)
    target_type = db.Column(db.String(60), index=True)
    target_id = db.Column(db.String(150), index=True)
    ip_address = db.Column(EncryptedString)
    request_id = db.Column(db.String(36), index=True)
    details = db.Column(EncryptedText)
    status = db.Column(db.String(20), index=True)

class RegistrationHistory(db.Model):
    __tablename__ = 'registration_history'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    hw_id = db.Column(db.String(100), index=True, nullable=False)
    hostname = db.Column(db.String(100))
    ip_address = db.Column(EncryptedString)
    event_type = db.Column(db.String(50))

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    module_name = db.Column(db.String(64))
    action = db.Column(db.String(128))
    targets = db.Column(db.Text)
    status = db.Column(db.String(32), default="Running")
    log_file = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)

class EndpointGroup(db.Model):
    __tablename__ = 'endpoint_groups'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), unique=True)
    description = db.Column(db.String(255))
    endpoints = db.relationship('Endpoint', secondary=endpoint_group_m2m, back_populates='groups')

class Endpoint(db.Model):
    __tablename__ = 'endpoints'
    id = db.Column(db.String(100), primary_key=True)
    hostname = db.Column(db.String(100))
    display_name = db.Column(db.String(120))
    auth_token = db.Column(db.String(255))
    public_key_pem = db.Column(EncryptedText)
    public_key_pem_plain = db.Column(db.Text)
    task_signing_private_key = db.Column(EncryptedText)
    task_signing_public_key = db.Column(db.Text)
    task_signing_key_id = db.Column(db.String(64), index=True)
    task_signing_sequence = db.Column(db.BigInteger, default=0)
    task_signature_v2_seen_at = db.Column(db.DateTime, nullable=True)
    os_version = db.Column(db.String(100))
    os_type = db.Column(db.String(50), default="Windows")
    connection_ip = db.Column(db.String(64), index=True)
    ip_address = db.Column(EncryptedString)
    approval_status = db.Column(db.String(20), default="Pending", index=True)
    agent_version = db.Column(db.String(50))
    network_info = db.Column(EncryptedText)
    host_info = db.Column(EncryptedText)
    encryption_status = db.Column(db.String(40), default="Unknown", index=True)
    encryption_level = db.Column(db.String(20), default="unknown", index=True)
    encryption_methods = db.Column(db.String(120), default="")
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_enrollment_at = db.Column(db.DateTime, nullable=True, index=True)
    last_enrollment_ip = db.Column(EncryptedString)
    enrollment_attempts = db.Column(db.Integer, default=0)
    identity_fingerprint = db.Column(db.String(64))
    identity_warning = db.Column(db.String(255))
    identity_duplicate_allowed = db.Column(db.Boolean, default=False, index=True)
    reenroll_allowed_until = db.Column(db.DateTime, nullable=True, index=True)

    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_blocked = db.Column(db.Boolean, default=False, index=True)

    groups = db.relationship('EndpointGroup', secondary=endpoint_group_m2m, back_populates='endpoints')
    # Execution history must survive endpoint removal. Hard endpoint deletion is
    # additionally restricted at the route layer and snapshots are stored on the
    # task itself for long-term audit readability.
    tasks = db.relationship('AgentTask', back_populates='endpoint', passive_deletes=True)
    telemetry = db.relationship('TelemetryHistory', back_populates='endpoint', cascade="all, delete-orphan", lazy='dynamic')
    metrics = db.relationship('EndpointMetric', back_populates='endpoint', cascade="all, delete-orphan", lazy='dynamic')

class EndpointDuplicateException(db.Model):
    __tablename__ = 'endpoint_duplicate_exceptions'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    endpoint_a_id = db.Column(db.String(100), db.ForeignKey('endpoints.id', ondelete="CASCADE"), nullable=False, index=True)
    endpoint_b_id = db.Column(db.String(100), db.ForeignKey('endpoints.id', ondelete="CASCADE"), nullable=False, index=True)
    reason = db.Column(db.String(255))
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.UniqueConstraint('endpoint_a_id', 'endpoint_b_id', name='uq_endpoint_duplicate_exception_pair'),
    )

class AgentTask(db.Model):
    __tablename__ = 'agent_tasks'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = db.Column(db.String(36), index=True)
    endpoint_id = db.Column(db.String(100), db.ForeignKey('endpoints.id', ondelete="SET NULL"), nullable=True, index=True)
    endpoint_id_snapshot = db.Column(db.String(100), nullable=True, index=True)
    endpoint_hostname_snapshot = db.Column(db.String(100), nullable=True, index=True)
    endpoint_name_snapshot = db.Column(db.String(120), nullable=True, index=True)
    endpoint_groups_snapshot = db.Column(db.Text)

    title = db.Column(db.String(150), default="Untitled Task")
    module_source = db.Column(db.String(50))
    action_type = db.Column(db.String(50))
    source_type = db.Column(db.String(30), default="manual", index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True, index=True)
    template_id = db.Column(db.String(36), nullable=True, index=True)
    schedule_id = db.Column(db.String(36), nullable=True, index=True)
    payload = db.Column(EncryptedText)
    status = db.Column(db.String(20), default="Pending", index=True)
    result_log = db.Column(EncryptedText)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    finished_at = db.Column(db.DateTime)
    created_by = db.Column(db.String(100))

    endpoint = db.relationship('Endpoint', back_populates='tasks')

class TelemetryHistory(db.Model):
    __tablename__ = 'telemetry_history'
    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.String(100), db.ForeignKey('endpoints.id', ondelete="CASCADE"), index=True)

    cpu_usage = db.Column(db.Float)
    ram_usage = db.Column(db.Float)
    disk_c_free = db.Column(db.Float)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    endpoint = db.relationship('Endpoint', back_populates='telemetry')

class ConnectionIpHistory(db.Model):
    __tablename__ = 'connection_ip_history'
    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.String(100), db.ForeignKey('endpoints.id', ondelete="CASCADE"), index=True)
    ip_address = db.Column(EncryptedString)
    source = db.Column(db.String(50), default="agent")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    endpoint = db.relationship('Endpoint')

class TaskTemplate(db.Model):
    __tablename__ = 'task_templates'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), default="General")
    action_type = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(50), default="action")
    payload = db.Column(EncryptedText)
    is_approved = db.Column(db.Boolean, default=False)
    approved_content_hash = db.Column(db.String(64), index=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    approved_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(100))

class ScheduledTask(db.Model):
    __tablename__ = 'scheduled_tasks'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), default="Scheduled")

    template_id = db.Column(db.String(36), db.ForeignKey('task_templates.id', ondelete="CASCADE"))
    target_type = db.Column(db.String(20))
    target_id = db.Column(db.String(100))

    cron_expr = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    variables = db.Column(EncryptedText)
    timeout_minutes = db.Column(db.Integer, nullable=True)
    next_run_at = db.Column(db.DateTime, nullable=True, index=True)
    last_status = db.Column(db.String(120), nullable=True)
    last_job_id = db.Column(db.String(36), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(100))
    last_run = db.Column(db.DateTime, nullable=True)

    template = db.relationship('TaskTemplate')

class EndpointMetric(db.Model):
    __tablename__ = 'endpoint_metrics'
    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.String(100), db.ForeignKey('endpoints.id', ondelete="CASCADE"), index=True)

    item_name = db.Column(db.String(150), index=True)
    last_value = db.Column(db.Text)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

    endpoint = db.relationship('Endpoint', back_populates='metrics')

class AgentUpdateRollout(db.Model):
    __tablename__ = 'agent_update_rollouts'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    package_id = db.Column(db.String(100), index=True)
    package_url = db.Column(db.Text)
    package_version = db.Column(db.String(50))
    target_ids = db.Column(db.Text)
    wave_size = db.Column(db.Integer, default=50)
    wave_delay_seconds = db.Column(db.Integer, default=300)
    next_wave_index = db.Column(db.Integer, default=1)
    total_waves = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default="Running", index=True)
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    next_run_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class TriggerRule(db.Model):
    __tablename__ = 'trigger_rules'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)

    target_group_id = db.Column(db.String(100), default="all")

    metric_name = db.Column(db.String(150), nullable=False)
    operator = db.Column(db.String(20), nullable=False)
    threshold_value = db.Column(db.String(255), nullable=False)

    action_template_id = db.Column(db.String(36), db.ForeignKey('task_templates.id', ondelete="SET NULL"), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    last_run = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(20), nullable=True)

# --- НОВЕ: МОДЕЛЬ ДЛЯ БУФЕРА ЗВІТІВ ---
class AggregatedJob(db.Model):
    """Буфер для зведених звітів після виконання задач на кількох хостах"""
    __tablename__ = 'aggregated_jobs'
    id = db.Column(db.String(36), primary_key=True) # Збігається з job_id
    title = db.Column(db.String(150))
    status = db.Column(db.String(20), default="Waiting Review") # Waiting Review, Sent, Dismissed
    report_data = db.Column(EncryptedText) # Зведений текст
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True, index=True)
    created_by = db.Column(db.String(150), nullable=True, index=True)
    source_type = db.Column(db.String(30), nullable=True, index=True)
    template_id = db.Column(db.String(36), nullable=True, index=True)
    original_content_hash = db.Column(db.String(64), nullable=True, index=True)
    current_revision_number = db.Column(db.Integer, default=0, nullable=False)
    success_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    total_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ReportRevision(db.Model):
    """Immutable generated/edited report body revision."""
    __tablename__ = 'report_revisions'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey('aggregated_jobs.id', ondelete="CASCADE"), nullable=False, index=True)
    revision_number = db.Column(db.Integer, nullable=False)
    kind = db.Column(db.String(30), nullable=False, default="edited", index=True)
    content = db.Column(EncryptedText, nullable=False)
    content_hash = db.Column(db.String(64), nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True, index=True)
    actor_name = db.Column(db.String(150), nullable=True, index=True)
    reason = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        db.UniqueConstraint('report_id', 'revision_number', name='uq_report_revision_number'),
    )


class ReportDelivery(db.Model):
    """Audit snapshot of the exact report revision sent to an external target."""
    __tablename__ = 'report_deliveries'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey('aggregated_jobs.id', ondelete="CASCADE"), nullable=False, index=True)
    revision_id = db.Column(db.String(36), db.ForeignKey('report_revisions.id', ondelete="RESTRICT"), nullable=False, index=True)
    channel = db.Column(db.String(30), nullable=False, index=True)
    destination = db.Column(EncryptedText)
    subject = db.Column(db.String(255), nullable=True)
    note = db.Column(EncryptedText)
    content_snapshot = db.Column(EncryptedText, nullable=False)
    content_hash = db.Column(db.String(64), nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True, index=True)
    actor_name = db.Column(db.String(150), nullable=True, index=True)
    status = db.Column(db.String(30), nullable=False, default="Pending", index=True)
    result_details = db.Column(EncryptedText)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = db.Column(db.DateTime, nullable=True, index=True)


class HistorySearchToken(db.Model):
    """Keyed blind-index token for encrypted history content."""
    __tablename__ = 'history_search_tokens'
    id = db.Column(db.Integer, primary_key=True)
    entity_type = db.Column(db.String(30), nullable=False)
    entity_id = db.Column(db.String(64), nullable=False)
    field = db.Column(db.String(30), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint(
            'entity_type', 'entity_id', 'field', 'token_hash',
            name='uq_history_search_token'
        ),
        db.Index('ix_history_search_token_lookup', 'token_hash', 'entity_type', 'field', 'entity_id'),
        db.Index('ix_history_search_token_entity', 'entity_type', 'entity_id'),
    )
