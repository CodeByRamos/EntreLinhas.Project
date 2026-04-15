from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
import database as db
from datetime import datetime

# Criação do Blueprint para as rotas de perfil
profile = Blueprint('profile', __name__)

@profile.route('/perfil/criar', methods=['GET', 'POST'])
def criar_perfil():
    """Rota para criar um novo perfil anônimo."""
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        bio = request.form.get('bio', '')
        
        # Validação básica
        if not nickname or len(nickname) < 3:
            flash('O apelido deve ter pelo menos 3 caracteres.', 'error')
            return render_template('profile/create.html')
        
        # Criar o perfil no banco de dados
        profile_id, token = db.create_profile(nickname, bio)
        
        # Armazenar o token na sessão
        session['profile_token'] = token
        
        # Redirecionar para a página do perfil
        return redirect(url_for('profile.ver_perfil'))
    
    return render_template('profile/create.html')

@profile.route('/perfil', methods=['GET'])
def ver_perfil():
    """Rota para visualizar o perfil anônimo do usuário."""
    # Verificar se o usuário tem um token de perfil
    token = session.get('profile_token')
    if not token:
        return redirect(url_for('profile.criar_perfil'))
    
    # Obter o perfil do banco de dados
    profile = db.get_profile_by_token(token)
    if not profile:
        # Token inválido ou perfil não encontrado
        session.pop('profile_token', None)
        return redirect(url_for('profile.criar_perfil'))
    
    # Obter os posts e comentários do perfil
    posts = db.get_posts_by_profile(profile['id'])
    comments = db.get_comments_by_profile(profile['id'])
    
    return render_template('profile/view.html', 
                          profile=profile,
                          posts=posts,
                          comments=comments)

@profile.route('/perfil/editar', methods=['GET', 'POST'])
def editar_perfil():
    """Rota para editar o perfil anônimo."""
    # Verificar se o usuário tem um token de perfil
    token = session.get('profile_token')
    if not token:
        return redirect(url_for('profile.criar_perfil'))
    
    # Obter o perfil do banco de dados
    profile = db.get_profile_by_token(token)
    if not profile:
        # Token inválido ou perfil não encontrado
        session.pop('profile_token', None)
        return redirect(url_for('profile.criar_perfil'))
    
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        bio = request.form.get('bio', '')
        
        # Validação básica
        if not nickname or len(nickname) < 3:
            flash('O apelido deve ter pelo menos 3 caracteres.', 'error')
            return render_template('profile/edit.html', profile=profile)
        
        # Atualizar o perfil no banco de dados
        db.update_profile(profile['id'], nickname, bio)
        
        # Redirecionar para a página do perfil
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('profile.ver_perfil'))
    
    return render_template('profile/edit.html', profile=profile)

@profile.route('/perfil/sair', methods=['GET'])
def sair_perfil():
    """Rota para sair do perfil anônimo."""
    # Remover o token da sessão
    session.pop('profile_token', None)
    
    # Redirecionar para a página inicial
    return redirect(url_for('main.home'))

@profile.route('/perfil/posts', methods=['GET'])
def posts_perfil():
    """Rota para visualizar os posts do perfil anônimo."""
    # Verificar se o usuário tem um token de perfil
    token = session.get('profile_token')
    if not token:
        return redirect(url_for('profile.criar_perfil'))
    
    # Obter o perfil do banco de dados
    profile = db.get_profile_by_token(token)
    if not profile:
        # Token inválido ou perfil não encontrado
        session.pop('profile_token', None)
        return redirect(url_for('profile.criar_perfil'))
    
    # Paginação
    page = request.args.get('page', 1, type=int)
    per_page = 5
    offset = (page - 1) * per_page
    
    # Obter os posts do perfil
    posts = db.get_posts_by_profile(profile['id'], limit=per_page, offset=offset)
    
    # Obter o total de posts para paginação
    total_posts = len(db.get_posts_by_profile(profile['id'], limit=1000))
    total_pages = (total_posts + per_page - 1) // per_page
    
    return render_template('profile/posts.html', 
                          profile=profile,
                          posts=posts,
                          page=page,
                          total_pages=total_pages)

@profile.route('/perfil/comentarios', methods=['GET'])
def comentarios_perfil():
    """Rota para visualizar os comentários do perfil anônimo."""
    # Verificar se o usuário tem um token de perfil
    token = session.get('profile_token')
    if not token:
        return redirect(url_for('profile.criar_perfil'))
    
    # Obter o perfil do banco de dados
    profile = db.get_profile_by_token(token)
    if not profile:
        # Token inválido ou perfil não encontrado
        session.pop('profile_token', None)
        return redirect(url_for('profile.criar_perfil'))
    
    # Paginação
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    # Obter os comentários do perfil
    comments = db.get_comments_by_profile(profile['id'], limit=per_page, offset=offset)
    
    # Obter o total de comentários para paginação
    total_comments = len(db.get_comments_by_profile(profile['id'], limit=1000))
    total_pages = (total_comments + per_page - 1) // per_page
    
    return render_template('profile/comments.html', 
                          profile=profile,
                          comments=comments,
                          page=page,
                          total_pages=total_pages)

