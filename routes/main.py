from flask import Blueprint, render_template

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return render_template('home.html')


@main.route('/sobre')
def about():
    return render_template('about.html')


@main.route('/como-funciona')
def how_it_works():
    return render_template('how_it_works.html')


@main.route('/privacidade')
def privacy():
    return render_template('privacy.html')


@main.route('/termos')
def terms():
    return render_template('terms.html')
