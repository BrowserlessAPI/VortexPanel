"""PHP Security (VortexPanel App) - entry point loaded by panel/plugins.py."""


def register(ctx):
    from vpapp_php_guard.api import bp
    ctx.register_blueprint(bp)
