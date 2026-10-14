"""Who is making the current request.

The central gate in app.py authenticates every /api/ request (session cookie
or API key) and stores the result in flask.g.vp_user; route modules use
authed() for their own legacy check so API-key requests are accepted too."""
from flask import g, session


def authed():
    return bool(g.get('vp_user')) or 'user' in session


def current_user():
    """{'uid', 'username', 'role', 'sites', 'via'} or None."""
    return g.get('vp_user')


def is_admin():
    u = g.get('vp_user')
    if u is None:
        return 'user' in session and session.get('role', 'admin') == 'admin'
    return u.get('role') == 'admin'
