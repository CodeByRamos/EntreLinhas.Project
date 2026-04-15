from flask import Blueprint, render_template, current_app

# Criação do Blueprint para as rotas principais
main = Blueprint('main', __name__)

@main.route('/')
def home():
    """Rota para a página inicial."""
    return render_template('home.html')

@main.route('/sobre')
def about():
    """Rota para a página 'Sobre o site'."""
    return render_template('about.html')

@main.route('/como-funciona')
def how_it_works():
    """Rota para a página 'Como funciona'."""
    return render_template('how_it_works.html')

