"""Website Statistics (VortexPanel App) - entry point loaded by panel/plugins.py."""


def register(ctx):
    from vpapp_site_stats.api import bp
    ctx.register_blueprint(bp)
