"""Sentinel IR — a learning-focused incident response platform.

Inspired by TheHive Project, Splunk SOAR, IBM Resilient, and ServiceNow SecOps.
Run with:  python app.py
Then visit http://127.0.0.1:5000
"""

import os
import json
from datetime import datetime, timedelta
from collections import Counter

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
)

from models import (
    db,
    User,
    Alert,
    Incident,
    Task,
    IOC,
    TimelineEntry,
    Playbook,
    SEVERITIES,
    ALERT_STATUSES,
    INCIDENT_STATUSES,
    CLASSIFICATIONS,
    CATEGORIES,
    TLP_LEVELS,
    IOC_TYPES,
    TASK_STATUSES,
)


BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'sentinel.db')}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = "sentinel-ir-demo-key-change-me"
    db.init_app(app)

    register_routes(app)

    @app.template_filter("dt")
    def fmt_dt(value):
        if not value:
            return "—"
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")

    @app.template_filter("ago")
    def fmt_ago(value):
        if not value:
            return "—"
        delta = datetime.utcnow() - value
        secs = int(delta.total_seconds())
        if secs < 60:
            return f"{secs}s ago"
        if secs < 3600:
            return f"{secs // 60}m ago"
        if secs < 86400:
            return f"{secs // 3600}h ago"
        return f"{secs // 86400}d ago"

    @app.template_filter("pretty_json")
    def pretty_json(value):
        try:
            return json.dumps(json.loads(value), indent=2)
        except Exception:
            return value

    @app.context_processor
    def inject_user():
        u = current_user()
        return {"current_user": u, "all_users": User.query.order_by(User.display_name).all()}

    return app


def current_user():
    uid = session.get("user_id")
    if uid:
        return User.query.get(uid)
    # default to first analyst
    return User.query.order_by(User.id).first()


def next_ticket_id():
    year = datetime.utcnow().year
    count = Incident.query.count() + 1
    return f"INC-{year}-{count:04d}"


def add_timeline(incident, entry_type, content, author=None):
    entry = TimelineEntry(
        incident_id=incident.id,
        entry_type=entry_type,
        content=content,
        author_id=(author or current_user()).id if (author or current_user()) else None,
    )
    db.session.add(entry)


def register_routes(app: Flask):

    # ---- Auth-lite (analyst switcher) ----
    @app.route("/switch_user", methods=["POST"])
    def switch_user():
        uid = int(request.form["user_id"])
        session["user_id"] = uid
        return redirect(request.referrer or url_for("dashboard"))

    # ---- Dashboard ----
    @app.route("/")
    def dashboard():
        now = datetime.utcnow()
        open_incidents = Incident.query.filter(Incident.status != "closed").all()
        new_alerts = Alert.query.filter_by(status="new").count()
        escalated = Alert.query.filter_by(status="escalated").count()

        sev_counts = Counter(i.severity for i in open_incidents)
        status_counts = Counter(i.status for i in open_incidents)
        cat_counts = Counter(i.category for i in open_incidents)

        # MTTR — mean time to closure (in hours)
        closed = Incident.query.filter(Incident.closed_at.isnot(None)).all()
        if closed:
            mttr_seconds = sum((i.closed_at - i.created_at).total_seconds() for i in closed) / len(closed)
            mttr_hours = round(mttr_seconds / 3600, 1)
        else:
            mttr_hours = None

        recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(8).all()
        recent_incidents = Incident.query.order_by(Incident.updated_at.desc()).limit(6).all()

        return render_template(
            "dashboard.html",
            new_alerts=new_alerts,
            escalated_alerts=escalated,
            open_incidents=open_incidents,
            sev_counts=sev_counts,
            status_counts=status_counts,
            cat_counts=cat_counts,
            mttr_hours=mttr_hours,
            recent_alerts=recent_alerts,
            recent_incidents=recent_incidents,
            severities=SEVERITIES,
            incident_statuses=INCIDENT_STATUSES,
        )

    # ---- Alerts ----
    @app.route("/alerts")
    def alerts():
        q = Alert.query
        status = request.args.get("status")
        severity = request.args.get("severity")
        source = request.args.get("source")
        if status:
            q = q.filter_by(status=status)
        if severity:
            q = q.filter_by(severity=severity)
        if source:
            q = q.filter_by(source=source)
        alerts = q.order_by(Alert.timestamp.desc()).all()

        sources = sorted({a.source for a in Alert.query.all()})
        return render_template(
            "alerts.html",
            alerts=alerts,
            severities=SEVERITIES,
            statuses=ALERT_STATUSES,
            sources=sources,
            f_status=status, f_severity=severity, f_source=source,
        )

    @app.route("/alerts/<int:alert_id>")
    def alert_detail(alert_id):
        alert = Alert.query.get_or_404(alert_id)
        return render_template("alert_detail.html", alert=alert,
                               statuses=ALERT_STATUSES,
                               severities=SEVERITIES)

    @app.route("/alerts/<int:alert_id>/status", methods=["POST"])
    def alert_status(alert_id):
        alert = Alert.query.get_or_404(alert_id)
        new_status = request.form["status"]
        if new_status not in ALERT_STATUSES:
            abort(400)
        alert.status = new_status
        db.session.commit()
        flash(f"Alert #{alert.id} marked {new_status}", "info")
        return redirect(url_for("alert_detail", alert_id=alert.id))

    @app.route("/alerts/<int:alert_id>/assign", methods=["POST"])
    def alert_assign(alert_id):
        alert = Alert.query.get_or_404(alert_id)
        uid = request.form.get("user_id")
        alert.assigned_to_id = int(uid) if uid else None
        db.session.commit()
        flash("Alert assignment updated", "info")
        return redirect(url_for("alert_detail", alert_id=alert.id))

    @app.route("/alerts/<int:alert_id>/promote", methods=["POST"])
    def alert_promote(alert_id):
        alert = Alert.query.get_or_404(alert_id)
        if alert.incident_id:
            flash("Alert already linked to an incident.", "warn")
            return redirect(url_for("alert_detail", alert_id=alert.id))

        category = request.form.get("category", "malware")
        priority = request.form.get("priority", "P3")

        incident = Incident(
            ticket_id=next_ticket_id(),
            title=f"[{alert.source}] {alert.title}",
            description=alert.description,
            severity=alert.severity,
            priority=priority,
            status="triage",
            category=category,
            assigned_to_id=current_user().id if current_user() else None,
            reporter_id=current_user().id if current_user() else None,
        )
        db.session.add(incident)
        db.session.flush()

        alert.incident_id = incident.id
        alert.status = "escalated"

        add_timeline(
            incident,
            "action",
            f"Incident created from alert #{alert.id} ({alert.source} — {alert.event_type})",
        )
        # auto-add observables from alert
        added = []
        if alert.src_ip:
            added.append(IOC(incident_id=incident.id, ioc_type="ip", value=alert.src_ip,
                             notes="Source IP from triggering alert"))
        if alert.dst_ip:
            added.append(IOC(incident_id=incident.id, ioc_type="ip", value=alert.dst_ip,
                             notes="Destination IP from triggering alert"))
        if alert.src_host:
            added.append(IOC(incident_id=incident.id, ioc_type="host", value=alert.src_host,
                             notes="Affected host"))
        if alert.src_user:
            added.append(IOC(incident_id=incident.id, ioc_type="user", value=alert.src_user,
                             notes="Involved user account"))
        for o in added:
            db.session.add(o)

        db.session.commit()
        flash(f"Incident {incident.ticket_id} created.", "success")
        return redirect(url_for("incident_detail", incident_id=incident.id))

    # ---- Incidents ----
    @app.route("/incidents")
    def incidents():
        q = Incident.query
        status = request.args.get("status")
        severity = request.args.get("severity")
        category = request.args.get("category")
        if status:
            q = q.filter_by(status=status)
        if severity:
            q = q.filter_by(severity=severity)
        if category:
            q = q.filter_by(category=category)
        items = q.order_by(Incident.updated_at.desc()).all()
        return render_template(
            "incidents.html",
            incidents=items,
            severities=SEVERITIES,
            statuses=INCIDENT_STATUSES,
            categories=CATEGORIES,
            f_status=status, f_severity=severity, f_category=category,
        )

    @app.route("/incidents/new", methods=["GET", "POST"])
    def incident_new():
        if request.method == "POST":
            incident = Incident(
                ticket_id=next_ticket_id(),
                title=request.form["title"],
                description=request.form.get("description", ""),
                severity=request.form.get("severity", "medium"),
                priority=request.form.get("priority", "P3"),
                status="new",
                category=request.form.get("category", "malware"),
                assigned_to_id=current_user().id if current_user() else None,
                reporter_id=current_user().id if current_user() else None,
            )
            db.session.add(incident)
            db.session.flush()
            add_timeline(incident, "action", "Incident manually created.")
            db.session.commit()
            flash(f"Incident {incident.ticket_id} created.", "success")
            return redirect(url_for("incident_detail", incident_id=incident.id))

        return render_template(
            "incident_new.html",
            severities=SEVERITIES,
            categories=CATEGORIES,
            priorities=["P1", "P2", "P3", "P4", "P5"],
        )

    @app.route("/incidents/<int:incident_id>")
    def incident_detail(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        playbooks = Playbook.query.filter_by(category=incident.category).all()
        return render_template(
            "incident_detail.html",
            incident=incident,
            severities=SEVERITIES,
            statuses=INCIDENT_STATUSES,
            classifications=CLASSIFICATIONS,
            categories=CATEGORIES,
            priorities=["P1", "P2", "P3", "P4", "P5"],
            tlp_levels=TLP_LEVELS,
            ioc_types=IOC_TYPES,
            task_statuses=TASK_STATUSES,
            playbooks=playbooks,
        )

    @app.route("/incidents/<int:incident_id>/status", methods=["POST"])
    def incident_status(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        new_status = request.form["status"]
        if new_status not in INCIDENT_STATUSES:
            abort(400)
        old = incident.status
        incident.status = new_status
        if new_status == "closed":
            incident.closed_at = datetime.utcnow()
            classification = request.form.get("classification")
            if classification:
                incident.classification = classification
        add_timeline(incident, "status_change",
                     f"Status changed: {old} → {new_status}")
        db.session.commit()
        flash(f"Status updated to {new_status}", "info")
        return redirect(url_for("incident_detail", incident_id=incident.id))

    @app.route("/incidents/<int:incident_id>/edit", methods=["POST"])
    def incident_edit(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        incident.title = request.form.get("title", incident.title)
        incident.description = request.form.get("description", incident.description)
        incident.severity = request.form.get("severity", incident.severity)
        incident.priority = request.form.get("priority", incident.priority)
        incident.category = request.form.get("category", incident.category)
        incident.classification = request.form.get("classification", incident.classification)
        assigned = request.form.get("assigned_to_id")
        incident.assigned_to_id = int(assigned) if assigned else None
        add_timeline(incident, "action", "Incident metadata updated.")
        db.session.commit()
        flash("Incident updated", "info")
        return redirect(url_for("incident_detail", incident_id=incident.id))

    @app.route("/incidents/<int:incident_id>/note", methods=["POST"])
    def incident_note(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        content = request.form["content"].strip()
        if content:
            add_timeline(incident, "note", content)
            db.session.commit()
        return redirect(url_for("incident_detail", incident_id=incident.id) + "#timeline")

    @app.route("/incidents/<int:incident_id>/evidence", methods=["POST"])
    def incident_evidence(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        content = request.form["content"].strip()
        if content:
            add_timeline(incident, "evidence", content)
            db.session.commit()
        return redirect(url_for("incident_detail", incident_id=incident.id) + "#timeline")

    @app.route("/incidents/<int:incident_id>/task", methods=["POST"])
    def incident_add_task(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        title = request.form["title"].strip()
        if not title:
            return redirect(url_for("incident_detail", incident_id=incident.id) + "#tasks")
        task = Task(
            incident_id=incident.id,
            title=title,
            description=request.form.get("description", ""),
            assigned_to_id=int(request.form["assigned_to_id"]) if request.form.get("assigned_to_id") else None,
        )
        db.session.add(task)
        add_timeline(incident, "action", f"Task created: {title}")
        db.session.commit()
        return redirect(url_for("incident_detail", incident_id=incident.id) + "#tasks")

    @app.route("/tasks/<int:task_id>/status", methods=["POST"])
    def task_status(task_id):
        task = Task.query.get_or_404(task_id)
        new_status = request.form["status"]
        if new_status not in TASK_STATUSES:
            abort(400)
        task.status = new_status
        if new_status == "done":
            task.completed_at = datetime.utcnow()
        add_timeline(task.incident, "action",
                     f"Task '{task.title}' → {new_status}")
        db.session.commit()
        return redirect(url_for("incident_detail", incident_id=task.incident_id) + "#tasks")

    @app.route("/incidents/<int:incident_id>/ioc", methods=["POST"])
    def incident_add_ioc(incident_id):
        incident = Incident.query.get_or_404(incident_id)
        ioc = IOC(
            incident_id=incident.id,
            ioc_type=request.form["ioc_type"],
            value=request.form["value"].strip(),
            tlp=request.form.get("tlp", "amber"),
            is_malicious=request.form.get("is_malicious") == "on",
            notes=request.form.get("notes", ""),
        )
        db.session.add(ioc)
        add_timeline(incident, "evidence",
                     f"Observable added — {ioc.ioc_type}: {ioc.value}")
        db.session.commit()
        return redirect(url_for("incident_detail", incident_id=incident.id) + "#iocs")

    @app.route("/iocs/<int:ioc_id>/delete", methods=["POST"])
    def ioc_delete(ioc_id):
        ioc = IOC.query.get_or_404(ioc_id)
        incident_id = ioc.incident_id
        db.session.delete(ioc)
        db.session.commit()
        return redirect(url_for("incident_detail", incident_id=incident_id) + "#iocs")

    # ---- Playbooks ----
    @app.route("/playbooks")
    def playbooks():
        items = Playbook.query.order_by(Playbook.category, Playbook.name).all()
        return render_template("playbooks.html", playbooks=items)

    @app.route("/playbooks/<int:playbook_id>")
    def playbook_detail(playbook_id):
        pb = Playbook.query.get_or_404(playbook_id)
        return render_template("playbook_detail.html", playbook=pb)

    # ---- Search ----
    @app.route("/search")
    def search():
        q = (request.args.get("q") or "").strip()
        alert_hits = []
        incident_hits = []
        ioc_hits = []
        if q:
            like = f"%{q}%"
            alert_hits = Alert.query.filter(
                db.or_(
                    Alert.title.ilike(like),
                    Alert.description.ilike(like),
                    Alert.src_ip.ilike(like),
                    Alert.dst_ip.ilike(like),
                    Alert.src_host.ilike(like),
                    Alert.src_user.ilike(like),
                    Alert.raw_log.ilike(like),
                )
            ).limit(50).all()
            incident_hits = Incident.query.filter(
                db.or_(
                    Incident.title.ilike(like),
                    Incident.description.ilike(like),
                    Incident.ticket_id.ilike(like),
                )
            ).limit(50).all()
            ioc_hits = IOC.query.filter(IOC.value.ilike(like)).limit(50).all()

        return render_template(
            "search.html",
            q=q,
            alert_hits=alert_hits,
            incident_hits=incident_hits,
            ioc_hits=ioc_hits,
        )


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            print("Empty database — run `python seed.py` to populate sample data.")
    app.run(debug=True, host="127.0.0.1", port=5000)
