from flask import Blueprint, session, render_template, flash, redirect, url_for, request
from model import get_db
from functools import wraps

audit_bp = Blueprint('audit', __name__, template_folder='templates')

# ---------------- DECORATORS ---------------- #
# Remove these if you're using the ones from main app.py
# Otherwise, keep these but remove the ones in main app.py to avoid duplication

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper

# ---------------- ROUTES ---------------- #
@audit_bp.route("/dashboard")
@admin_required
def dashboard():
    """Main admin dashboard showing overview and quick stats"""
    try:
        db = get_db()
        
        # Get recent activity stats
        recent_logs = db.execute("""
            SELECT COUNT(*) as count FROM audit_log 
            WHERE date(timestamp) = date('now')
        """).fetchone()['count']
        
        total_admins = db.execute("""
            SELECT COUNT(*) as count FROM admins
        """).fetchone()['count']
        
        # Get recent actions for quick view
        recent_actions = db.execute("""
            SELECT 
                al.action, 
                al.timestamp, 
                COALESCE(a.username, 'Unknown') as username,
                al.role
            FROM audit_log al
            LEFT JOIN admins a ON al.user_id = a.admin_key
            ORDER BY al.timestamp DESC
            LIMIT 5
        """).fetchall()
        
        stats = {
            'todays_actions': recent_logs,
            'total_admins': total_admins,
            'admin_name': session.get('username', 'Admin'),
            'recent_actions': recent_actions
        }
        
        return render_template("audit/dashboard.html", stats=stats)
    
    except Exception as e:
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return render_template("audit/dashboard.html", stats={
            'todays_actions': 0,
            'total_admins': 0,
            'admin_name': session.get('username', 'Admin'),
            'recent_actions': []
        })

@audit_bp.route("/logs")
@audit_bp.route("/logs/<int:page>")
@admin_required
def view_logs(page=1):
    """View paginated audit logs with filtering options"""
    try:
        db = get_db()
        per_page = 50
        offset = (page - 1) * per_page
        
        # Get filter parameters
        action_filter = request.args.get('action', '')
        date_filter = request.args.get('date', '')
        admin_filter = request.args.get('admin', '')
        
        # Build the query with filters
        where_clauses = []
        params = []
        
        if action_filter:
            where_clauses.append("al.action LIKE ?")
            params.append(f"%{action_filter}%")
        
        if date_filter:
            where_clauses.append("date(al.timestamp) = ?")
            params.append(date_filter)
            
        if admin_filter:
            where_clauses.append("a.username LIKE ?")
            params.append(f"%{admin_filter}%")
        
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
        
        # Get logs with pagination
        logs_query = f"""
            SELECT 
                al.id,
                al.action,
                al.role,
                al.timestamp,
                al.user_id,
                COALESCE(a.username, 'System/Unknown') as username
            FROM audit_log al
            LEFT JOIN admins a ON al.user_id = a.admin_key
            {where_sql}
            ORDER BY al.timestamp DESC
            LIMIT ? OFFSET ?
        """
        
        params.extend([per_page, offset])
        logs = db.execute(logs_query, params).fetchall()
        
        # Get total count for pagination
        count_query = f"""
            SELECT COUNT(*) as total
            FROM audit_log al
            LEFT JOIN admins a ON al.user_id = a.admin_key
            {where_sql}
        """
        total_count = db.execute(count_query, params[:-2]).fetchone()['total']
        
        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page
        has_prev = page > 1
        has_next = page < total_pages
        
        # Get unique actions and admins for filter dropdowns
        actions = db.execute("""
            SELECT DISTINCT action FROM audit_log 
            WHERE action IS NOT NULL 
            ORDER BY action
        """).fetchall()
        
        admins = db.execute("""
            SELECT DISTINCT username FROM admins 
            ORDER BY username
        """).fetchall()
        
        pagination_info = {
            'page': page,
            'total_pages': total_pages,
            'total_count': total_count,
            'has_prev': has_prev,
            'has_next': has_next,
            'prev_page': page - 1 if has_prev else None,
            'next_page': page + 1 if has_next else None
        }
        
        return render_template("audit/logs.html", 
                             logs=logs, 
                             pagination=pagination_info,
                             actions=[a['action'] for a in actions],
                             admins=[a['username'] for a in admins],
                             filters={
                                 'action': action_filter,
                                 'date': date_filter,
                                 'admin': admin_filter
                             })
    
    except Exception as e:
        flash(f"Error loading audit logs: {str(e)}", "danger")
        return render_template("audit/logs.html", 
                             logs=[], 
                             pagination={'page': 1, 'total_pages': 0, 'total_count': 0},
                             actions=[],
                             admins=[],
                             filters={})

@audit_bp.route("/logs/export")
@admin_required 
def export_logs():
    """Export audit logs as CSV"""
    try:
        from flask import make_response
        import csv
        from io import StringIO
        
        db = get_db()
        
        # Get all logs (or apply filters if needed)
        logs = db.execute("""
            SELECT 
                al.id,
                al.timestamp,
                COALESCE(a.username, 'System/Unknown') as username,
                al.role,
                al.action
            FROM audit_log al
            LEFT JOIN admins a ON al.user_id = a.admin_key
            ORDER BY al.timestamp DESC
        """).fetchall()
        
        # Create CSV content
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Timestamp', 'Admin', 'Role', 'Action'])
        
        # Write data
        for log in logs:
            writer.writerow([log['id'], log['timestamp'], log['username'], 
                           log['role'], log['action']])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
        
        return response
        
    except Exception as e:
        flash(f"Error exporting logs: {str(e)}", "danger")
        return redirect(url_for('audit.view_logs'))

@audit_bp.route("/stats")
@admin_required
def view_stats():
    """View audit statistics and analytics"""
    try:
        db = get_db()
        
        # Action frequency
        action_stats = db.execute("""
            SELECT action, COUNT(*) as count
            FROM audit_log
            WHERE action IS NOT NULL
            GROUP BY action
            ORDER BY count DESC
        """).fetchall()
        
        # Daily activity (last 30 days)
        daily_stats = db.execute("""
            SELECT date(timestamp) as date, COUNT(*) as count
            FROM audit_log
            WHERE timestamp >= date('now', '-30 days')
            GROUP BY date(timestamp)
            ORDER BY date DESC
        """).fetchall()
        
        # Admin activity
        admin_stats = db.execute("""
            SELECT 
                COALESCE(a.username, 'System/Unknown') as admin,
                COUNT(*) as actions
            FROM audit_log al
            LEFT JOIN admins a ON al.user_id = a.admin_key
            GROUP BY a.username
            ORDER BY actions DESC
        """).fetchall()
        
        stats = {
            'action_stats': action_stats,
            'daily_stats': daily_stats,
            'admin_stats': admin_stats
        }
        
        return render_template("audit/stats.html", stats=stats)
        
    except Exception as e:
        flash(f"Error loading statistics: {str(e)}", "danger")
        return render_template("audit/stats.html", stats={
            'action_stats': [],
            'daily_stats': [],
            'admin_stats': []
        })
