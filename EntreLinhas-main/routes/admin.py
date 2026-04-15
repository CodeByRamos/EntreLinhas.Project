from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
import database as db
import functools

# Criação do Blueprint para as rotas administrativas
admin = Blueprint('admin', __name__, url_prefix='/admin')

# Configurações de autenticação simples
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "senha_segura_123"  # Em produção, usar hash e armazenar em variável de ambiente

# Decorator para verificar se o usuário está autenticado como admin
def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('admin_logged_in'):
            flash('Acesso restrito. Faça login como administrador.', 'error')
            return redirect(url_for('admin.login'))
        return view(**kwargs)
    return wrapped_view

@admin.route('/login', methods=['GET', 'POST'])
def login():
    """Rota para login administrativo."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Credenciais inválidas. Tente novamente.', 'error')
    
    return render_template('admin/login.html')

@admin.route('/logout')
def logout():
    """Rota para logout administrativo."""
    session.pop('admin_logged_in', None)
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('admin.login'))

@admin.route('/')
@admin_required
def dashboard():
    """Rota para o painel administrativo."""
    # Obter estatísticas básicas
    stats = {
        'total_posts': db.get_post_count(),
        'total_comments': db.get_comment_count(),
        'total_reactions': db.get_reaction_count(),
        'hidden_posts': db.get_hidden_post_count(),
        'hidden_comments': db.get_hidden_comment_count()
    }
    
    return render_template('admin/dashboard.html', stats=stats)

@admin.route('/posts')
@admin_required
def posts():
    """Rota para gerenciar posts."""
    # Parâmetros de filtro
    visibility = request.args.get('visibility', 'all')
    
    # Obter posts com base no filtro
    if visibility == 'visible':
        posts_list = db.get_posts(include_hidden=False)
    elif visibility == 'hidden':
        posts_list = db.get_hidden_posts()
    else:  # 'all'
        posts_list = db.get_posts(include_hidden=True)
    
    return render_template('admin/posts.html', posts=posts_list, visibility=visibility)

@admin.route('/comments')
@admin_required
def comments():
    """Rota para gerenciar comentários."""
    # Parâmetros de filtro
    visibility = request.args.get('visibility', 'all')
    post_id = request.args.get('post_id')
    
    # Obter comentários com base no filtro
    if post_id:
        if visibility == 'visible':
            comments_list = db.get_comments(post_id, include_hidden=False)
        elif visibility == 'hidden':
            comments_list = db.get_hidden_comments(post_id)
        else:  # 'all'
            comments_list = db.get_comments(post_id, include_hidden=True)
    else:
        if visibility == 'visible':
            comments_list = db.get_all_comments(include_hidden=False)
        elif visibility == 'hidden':
            comments_list = db.get_all_hidden_comments()
        else:  # 'all'
            comments_list = db.get_all_comments(include_hidden=True)
    
    return render_template('admin/comments.html', comments=comments_list, visibility=visibility, post_id=post_id)

@admin.route('/post/<int:post_id>/toggle_visibility', methods=['POST'])
@admin_required
def toggle_post_visibility(post_id):
    """Rota para alternar a visibilidade de um post."""
    post = db.get_post(post_id, include_hidden=True)
    if not post:
        flash('Post não encontrado.', 'error')
        return redirect(url_for('admin.posts'))
    
    # Alternar visibilidade
    new_visibility = 0 if post['visivel'] == 1 else 1
    db.update_post_visibility(post_id, new_visibility)
    
    action = "ocultado" if new_visibility == 0 else "tornado visível"
    flash(f'Post #{post_id} foi {action} com sucesso!', 'success')
    
    # Redirecionar de volta para a página anterior
    return redirect(request.referrer or url_for('admin.posts'))

@admin.route('/comment/<int:comment_id>/toggle_visibility', methods=['POST'])
@admin_required
def toggle_comment_visibility(comment_id):
    """Rota para alternar a visibilidade de um comentário."""
    comment = db.get_comment_by_id(comment_id, include_hidden=True)
    if not comment:
        flash('Comentário não encontrado.', 'error')
        return redirect(url_for('admin.comments'))
    
    # Alternar visibilidade
    new_visibility = 0 if comment['visivel'] == 1 else 1
    db.update_comment_visibility(comment_id, new_visibility)
    
    action = "ocultado" if new_visibility == 0 else "tornado visível"
    flash(f'Comentário #{comment_id} foi {action} com sucesso!', 'success')
    
    # Redirecionar de volta para a página anterior
    return redirect(request.referrer or url_for('admin.comments'))


@admin.route('/comment-reports')
@admin_required
def comment_reports():
    """Rota para gerenciar reports de comentários."""
    try:
        # Obter todos os reports de comentários (pendentes por padrão)
        reports = db.get_comment_reports(resolved=0)
        
        return render_template('admin/comment_reports.html', reports=reports)
    except Exception as e:
        flash(f'Erro ao carregar reports de comentários: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

@admin.route('/comment-reports/<int:report_id>/resolve', methods=['POST'])
@admin_required
def resolve_comment_report(report_id):
    """Rota para resolver um report de comentário (admin)."""
    try:
        success = db.resolve_comment_report(report_id)
        
        if success:
            return jsonify({
                'success': True, 
                'message': 'Report de comentário resolvido com sucesso.'
            })
        else:
            return jsonify({'success': False, 'message': 'Erro ao resolver report de comentário.'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

@admin.route('/comment-reports/<int:report_id>/remove', methods=['DELETE'])
@admin_required
def remove_comment_report(report_id):
    """Rota para remover um report de comentário (admin)."""
    try:
        success = db.remove_comment_report(report_id)
        
        if success:
            return jsonify({
                'success': True, 
                'message': 'Report de comentário removido com sucesso.'
            })
        else:
            return jsonify({'success': False, 'message': 'Erro ao remover report de comentário.'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

