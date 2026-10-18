"""Who is making the current request.

The central gate in app.py authenticates every /api/ request (session cookie
or API key) and stores the result in flask.g.vp_user; route modules use
authed() for their own legacy check so API-key requests are accepted too."""
import contextvars
from contextlib import contextmanager

from flask import g, session

# Plugins (the Hosting Module's customer portal) call core route functions on
# a customer's behalf after their own ownership checks. They do it inside
# `with elevate():` - a request-scoped flag no client can set, which
# authed() honours. It is never stored in the session.
_elevated = contextvars.ContextVar('vp_elevated', default=False)


@contextmanager
def elevate():
    token = _elevated.set(True)
    try:
        yield
    finally:
        _elevated.reset(token)


def is_elevated():
    return _elevated.get()


def authed():
    return bool(g.get('vp_user')) or 'user' in session or _elevated.get()


def current_user():
    """{'uid', 'username', 'role', 'sites', 'via'} or None."""
    return g.get('vp_user')


def is_admin():
    u = g.get('vp_user')
    if u is None:
        return 'user' in session and session.get('role', 'admin') == 'admin'
    return u.get('role') == 'admin'
