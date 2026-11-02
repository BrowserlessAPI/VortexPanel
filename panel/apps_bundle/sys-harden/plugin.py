"""System Hardening (VortexPanel App) - entry point loaded by panel/plugins.py."""


def register(ctx):
    from vpapp_sys_harden.api import bp
    ctx.register_blueprint(bp)
