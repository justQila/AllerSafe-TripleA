from flask import Blueprint, session
from models import get_db

audit_bp = Blueprint('audit', __name__)


def login_required(f):
    from functools import wraps
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return "Login required", 403
        return f(*args, **kwargs)
    return wraps(f)(wrapper)


def admin_required(f):
    from functools import wraps
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return "Admins only", 403
        return f(*args, **kwargs)
    return wraps(f)(wrapper)
