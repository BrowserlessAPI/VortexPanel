"""Network Scan Detection (VortexPanel App) - entry point loaded by panel/plugins.py."""


def register(ctx):
    from vpapp_scan_detect.api import bp
    ctx.register_blueprint(bp)
