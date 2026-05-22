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
    db.Column('group_id', db.String(36), db.ForeignKey('endpoint_groups.id', ondelete="CASCADE"), primary_key=True)
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
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref=db.backref('api_keys', cascade="all, delete-orphan"))

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user = db.Column(db.String(100))
    actor_type = db.Column(db.String(20), default="user", index=True)
    actor_name = db.Column(db.String(150), index=True)
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
    auth_token = db.Column(db.String(255))
    public_key_pem = db.Column(EncryptedText) 
    os_version = db.Column(db.String(100))
    os_type = db.Column(db.String(50), default="Windows") 
    ip_address = db.Column(EncryptedString)
    approval_status = db.Column(db.String(20), default="Pending", index=True)
    agent_version = db.Column(db.String(50))
    network_info = db.Column(EncryptedText)
    host_info = db.Column(EncryptedText)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_enrollment_at = db.Column(db.DateTime, nullable=True, index=True)
    last_enrollment_ip = db.Column(EncryptedString)
    enrollment_attempts = db.Column(db.Integer, default=0)
    identity_fingerprint = db.Column(db.String(64))
    identity_warning = db.Column(db.String(255))
    
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_blocked = db.Column(db.Boolean, default=False, index=True)
    
    groups = db.relationship('EndpointGroup', secondary=endpoint_group_m2m, back_populates='endpoints')
    tasks = db.relationship('AgentTask', back_populates='endpoint', cascade="all, delete-orphan")
    telemetry = db.relationship('TelemetryHistory', back_populates='endpoint', cascade="all, delete-orphan", lazy='dynamic')
    metrics = db.relationship('EndpointMetric', back_populates='endpoint', cascade="all, delete-orphan", lazy='dynamic')

class AgentTask(db.Model):
    __tablename__ = 'agent_tasks'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = db.Column(db.String(36), index=True)
    endpoint_id = db.Column(db.String(100), db.ForeignKey('endpoints.id', ondelete="CASCADE"), index=True)
    
    title = db.Column(db.String(150), default="Untitled Task")
    module_source = db.Column(db.String(50))
    action_type = db.Column(db.String(50)) 
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

class TaskTemplate(db.Model):
    __tablename__ = 'task_templates'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), default="General") 
    action_type = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(50), default="action") 
    payload = db.Column(EncryptedText)
    is_approved = db.Column(db.Boolean, default=False)
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
    success_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    total_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
