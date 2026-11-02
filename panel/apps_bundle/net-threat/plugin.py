"""Network Threat Detection (VortexPanel App) - entry point loaded by panel/plugins.py."""


def register(ctx):
    from vpapp_net_threat.api import bp
    ctx.register_blueprint(bp)
