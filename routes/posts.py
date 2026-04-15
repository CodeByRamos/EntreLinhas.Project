from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from datetime import datetime
import database as db

# Criação do Blueprint para as rotas de posts (desabafos)
posts = Blueprint('posts', __name__)

@posts.route('/feed')
def feed():
    """Rota para a página de feed de desabafos."""
    # Obter parâmetros de filtro e paginação
    categoria = request.args.get('categoria', '')
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Número de posts por página
    
    # Calcular o offset para paginação
    offset = (page - 1) * per_page
    
    # Obter desabafos com base nos filtros e paginação
    if categoria:
        desabafos = db.get_posts_by_category(categoria, limit=per_page, offset=offset)
        total_posts = db.get_post_count_by_category(categoria)
    else:
        desabafos = db.get_posts(limit=per_page, offset=offset)
        total_posts = db.get_post_count()
    
    # Calcular número total de páginas
    total_pages = (total_posts + per_page - 1) // per_page  # Arredondamento para cima
    
    # Obter categorias disponíveis para o filtro
    categorias_disponiveis = db.get_categories()
    
    # Usar categorias da configuração para o formulário
    categorias_form = current_app.config['CATEGORIAS']
    reacoes = current_app.config['REACOES']
    
    return render_template('feed.html', 
                          desabafos=desabafos, 
                          categorias=categorias_form,
                          categorias_disponiveis=categorias_disponiveis,
                          categoria_atual=categoria,
                          reacoes=reacoes,
                          page=page,
                          total_pages=total_pages)

@posts.route('/feed/categoria/<categoria>')
def filtrar_categoria(categoria):
    """Rota para filtrar desabafos por categoria."""
    # Redireciona para a rota principal do feed com o parâmetro de categoria
    page = request.args.get('page', 1, type=int)
    return redirect(url_for('posts.feed', categoria=categoria, page=page))

@posts.route('/enviar', methods=['POST'])
def enviar():
    """Rota para enviar um novo desabafo."""
    if request.method == 'POST':
        conteudo = request.form.get('conteudo')
        categoria = request.form.get('categoria')
        
        if not conteudo or not categoria:
            flash('Por favor, preencha todos os campos.')
            return redirect(url_for('posts.feed'))
        
        # Cria o post no banco de dados
        post_id = db.create_post(conteudo, categoria)
        
        return redirect(url_for('posts.feed'))
    
    return redirect(url_for('posts.feed'))

@posts.route('/categorias')
def get_categorias():
    """Rota para obter as categorias disponíveis (API)."""
    categorias = db.get_categories()
    return jsonify(categorias)

