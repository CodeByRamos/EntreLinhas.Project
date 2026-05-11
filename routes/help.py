from flask import Blueprint, render_template
import database as db

support = Blueprint('support', __name__)


@support.route('/ajuda')
def ajuda():
    volunteers = db.get_active_help_volunteers()
    return render_template('help.html', volunteers=volunteers)
