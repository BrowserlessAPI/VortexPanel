from flask import Blueprint, render_template
from panel.routes.update import get_current_version
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html', panel_version=get_current_version())
