"""Database models for the IR platform.

Modeled after concepts used in TheHive, Splunk SOAR, IBM Resilient, and
ServiceNow Security Operations.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


SEVERITIES = ["info", "low", "medium", "high", "critical"]

ALERT_STATUSES = ["new", "acknowledged", "escalated", "closed_false_positive"]

INCIDENT_STATUSES = [
    "new",
    "triage",
    "investigating",
    "contained",
    "eradicated",
    "recovered",
    "closed",
]

CLASSIFICATIONS = [
    "unclassified",
    "true_positive",
    "false_positive",
    "benign",
    "duplicate",
]

CATEGORIES = [
    "malware",
    "phishing",
    "unauthorized_access",
    "data_exfiltration",
    "denial_of_service",
    "insider_threat",
    "policy_violation",
    "credential_compromise",
    "ransomware",
    "web_attack",
    "reconnaissance",
]

TLP_LEVELS = ["white", "green", "amber", "red"]

IOC_TYPES = ["ip", "domain", "url", "hash_md5", "hash_sha256", "email", "user", "host", "file", "registry"]

TASK_STATUSES = ["todo", "in_progress", "blocked", "done"]


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    display_name = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="analyst")  # analyst, lead, manager

    def __repr__(self):
        return f"<User {self.username}>"


class Alert(db.Model):
    """A raw security event from a detection source (SIEM, EDR, IDS, etc.)."""

    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source = db.Column(db.String(64), nullable=False)  # e.g. CrowdStrike, Splunk, Suricata
    event_type = db.Column(db.String(128), nullable=False)
    severity = db.Column(db.String(16), nullable=False, default="low")
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    raw_log = db.Column(db.Text, nullable=False, default="")

    src_ip = db.Column(db.String(64))
    dst_ip = db.Column(db.String(64))
    src_user = db.Column(db.String(128))
    src_host = db.Column(db.String(128))

    mitre_tactic = db.Column(db.String(64))
    mitre_technique = db.Column(db.String(64))

    status = db.Column(db.String(32), nullable=False, default="new", index=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    assigned_to = db.relationship("User", foreign_keys=[assigned_to_id])

    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), index=True)
    incident = db.relationship("Incident", back_populates="alerts")


class Incident(db.Model):
    """A confirmed or suspected security incident under investigation."""

    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(32), unique=True, nullable=False, index=True)  # INC-2026-0001
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime)

    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    severity = db.Column(db.String(16), nullable=False, default="medium")
    priority = db.Column(db.String(16), nullable=False, default="P3")  # P1 highest, P5 lowest
    status = db.Column(db.String(32), nullable=False, default="new", index=True)
    classification = db.Column(db.String(32), nullable=False, default="unclassified")
    category = db.Column(db.String(64), nullable=False, default="malware")

    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    assigned_to = db.relationship("User", foreign_keys=[assigned_to_id])
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    reporter = db.relationship("User", foreign_keys=[reporter_id])

    alerts = db.relationship("Alert", back_populates="incident")
    tasks = db.relationship("Task", back_populates="incident", cascade="all, delete-orphan")
    iocs = db.relationship("IOC", back_populates="incident", cascade="all, delete-orphan")
    timeline = db.relationship(
        "TimelineEntry",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="TimelineEntry.timestamp",
    )


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False)
    incident = db.relationship("Incident", back_populates="tasks")

    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(32), nullable=False, default="todo")
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    assigned_to = db.relationship("User", foreign_keys=[assigned_to_id])

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)


class IOC(db.Model):
    """Observable / Indicator of Compromise."""

    __tablename__ = "iocs"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False)
    incident = db.relationship("Incident", back_populates="iocs")

    ioc_type = db.Column(db.String(32), nullable=False)
    value = db.Column(db.String(512), nullable=False, index=True)
    tlp = db.Column(db.String(16), nullable=False, default="amber")
    is_malicious = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class TimelineEntry(db.Model):
    __tablename__ = "timeline_entries"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False)
    incident = db.relationship("Incident", back_populates="timeline")

    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = db.relationship("User", foreign_keys=[author_id])
    entry_type = db.Column(db.String(32), nullable=False, default="note")  # note, action, status_change, evidence
    content = db.Column(db.Text, nullable=False)


class Playbook(db.Model):
    """A canned response procedure (runbook) for a given incident category."""

    __tablename__ = "playbooks"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    category = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False)
    steps = db.Column(db.Text, nullable=False)  # newline-separated steps
