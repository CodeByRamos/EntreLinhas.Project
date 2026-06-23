from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
import database as db
import functools
from utils.roles import ROLE_ORDER, ROLE_LABELS, normalize_role
from extensions import limiter

# Criação do Blueprint para as rotas administrativas
admin = Blueprint('admin', __name__, url_prefix='/admin')

# Decorator para verificar se o usuário está autenticado como admin
def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        admin_user_id = session.get('admin_user_id')
        if not session.get('admin_logged_in') or not admin_user_id:
            flash('Acesso restrito. Faça login como administrador.', 'error')
            return redirect(url_for('admin.login'))
        admin_user = db.get_user_by_id(admin_user_id)
        if not admin_user or not admin_user['is_admin']:
            session.pop('admin_logged_in', None)
            session.pop('admin_user_id', None)
            session.pop('admin_username', None)
            flash('Sua sessão administrativa expirou. Faça login novamente.', 'error')
            return redirect(url_for('admin.login'))
        return view(**kwargs)
    return wrapped_view

@admin.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute; 20 per hour', methods=['POST'])
def login():
    """Rota para login administrativo."""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        admin_user = db.authenticate_admin(username, password)
        if admin_user:
            session['admin_logged_in'] = True
            session['admin_user_id'] = admin_user['id']
            session['admin_username'] = admin_user['username']
            flash('Você entrou na moderação.', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Não encontramos uma conta administrativa com esses dados.', 'error')
    
    return render_template('admin/login.html')

@admin.route('/logout')
def logout():
    """Rota para logout administrativo."""
    session.pop('admin_logged_in', None)
    session.pop('admin_user_id', None)
    session.pop('admin_username', None)
    flash('Você saiu da moderação.', 'success')
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
    stats.update(db.get_moderation_stats())
    
    return render_template('admin/dashboard.html', stats=stats)

@admin.route('/posts')
@admin_required
def posts():
    """Rota para gerenciar posts."""
    # Parâmetros de filtro
    visibility = request.args.get('visibility', 'all')
    
    posts_list = db.get_admin_posts(filter_mode=visibility, limit=80)
    
    return render_template('admin/posts.html', posts=posts_list, visibility=visibility)


@admin.route('/reports')
@admin_required
def post_reports():
    status = request.args.get('status', 'pending')
    if status not in ('pending', 'resolved', 'dismissed', 'all'):
        status = 'pending'
    reports_list = db.get_all_reports(status=None if status == 'all' else status, limit=80)
    return render_template('admin/reports.html', reports=reports_list, status=status)


@admin.route('/reports/<int:report_id>/resolve', methods=['POST'])
@admin_required
def resolve_post_report(report_id):
    action = request.form.get('action', 'resolved')
    if action not in ('resolved', 'dismissed'):
        action = 'resolved'
    if db.resolve_report(report_id, status=action):
        flash('Aviso marcado como cuidado pela moderação.', 'success')
    else:
        flash('Não conseguimos atualizar esse aviso agora.', 'error')
    return redirect(request.referrer or url_for('admin.post_reports'))

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
        flash('Esse desabafo não está mais disponível.', 'error')
        return redirect(url_for('admin.posts'))
    
    # Alternar visibilidade
    new_visibility = 0 if post['visivel'] == 1 else 1
    db.update_post_visibility(post_id, new_visibility)
    
    action = "ocultado" if new_visibility == 0 else "tornado visível"
    flash(f'Desabafo {action}.', 'success')
    
    # Redirecionar de volta para a página anterior
    return redirect(request.referrer or url_for('admin.posts'))

@admin.route('/comment/<int:comment_id>/toggle_visibility', methods=['POST'])
@admin_required
def toggle_comment_visibility(comment_id):
    """Rota para alternar a visibilidade de um comentário."""
    comment = db.get_comment_by_id(comment_id, include_hidden=True)
    if not comment:
        flash('Essa resposta não está mais disponível.', 'error')
        return redirect(url_for('admin.comments'))
    
    # Alternar visibilidade
    new_visibility = 0 if comment['visivel'] == 1 else 1
    db.update_comment_visibility(comment_id, new_visibility)
    
    action = "ocultado" if new_visibility == 0 else "tornado visível"
    flash(f'Resposta {action}.', 'success')
    
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
        flash('Não conseguimos carregar os avisos de respostas agora.', 'error')
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
                'message': 'Aviso de resposta marcado como resolvido.'
            })
        else:
            return jsonify({'success': False, 'message': 'Não conseguimos resolver esse aviso agora.'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Não conseguimos resolver esse aviso agora.'}), 500

@admin.route('/comment-reports/<int:report_id>/remove', methods=['DELETE'])
@admin_required
def remove_comment_report(report_id):
    """Rota para remover um report de comentário (admin)."""
    try:
        success = db.remove_comment_report(report_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Aviso de resposta removido.'
            })
        else:
            return jsonify({'success': False, 'message': 'Não conseguimos remover esse aviso agora.'}), 500

    except Exception as e:
        return jsonify({'success': False, 'message': 'Não conseguimos remover esse aviso agora.'}), 500


@admin.route('/moderacao')
@admin_required
def moderation_queue():
    """Fila de revisão: desabafos sensíveis + respostas denunciadas + histórico."""
    return render_template(
        'admin/moderation.html',
        sensitive_posts=db.get_sensitive_posts_for_queue(limit=80),
        reported_comments=db.get_reported_comments_for_queue(limit=80),
        counts=db.get_moderation_queue_counts(),
        history=db.get_moderation_actions(limit=40),
    )


_MOD_POST_ACTIONS = ('approve', 'review', 'hide', 'remove')
_MOD_COMMENT_ACTIONS = ('approve', 'review', 'hide', 'remove')


@admin.route('/moderacao/post/<int:post_id>/<action>', methods=['POST'])
@admin_required
def moderate_post(post_id, action):
    if action not in _MOD_POST_ACTIONS:
        flash('Ação de moderação inválida.', 'error')
        return redirect(url_for('admin.moderation_queue'))
    post = db.get_post(post_id, include_hidden=True)
    if not post:
        flash('Esse desabafo não está mais disponível.', 'error')
        return redirect(url_for('admin.moderation_queue'))

    notes = request.form.get('notes', '').strip()
    if action in ('approve', 'review'):
        db.clear_post_sensitive_flag(post_id)
        msg = 'Desabafo aprovado e mantido.' if action == 'approve' else 'Desabafo revisado.'
    elif action == 'hide':
        db.update_post_visibility(post_id, 0)
        msg = 'Desabafo ocultado do feed.'
    else:  # remove
        db.soft_delete_post(post_id)
        msg = 'Desabafo removido.'

    db.log_moderation_action('post', post_id, action,
                             moderator_id=session.get('admin_user_id'),
                             moderator_username=session.get('admin_username'),
                             notes=notes)
    flash(msg, 'success')
    return redirect(url_for('admin.moderation_queue'))


@admin.route('/moderacao/comment/<int:comment_id>/<action>', methods=['POST'])
@admin_required
def moderate_comment(comment_id, action):
    if action not in _MOD_COMMENT_ACTIONS:
        flash('Ação de moderação inválida.', 'error')
        return redirect(url_for('admin.moderation_queue'))
    comment = db.get_comment_by_id(comment_id, include_hidden=True)
    if not comment:
        flash('Essa resposta não está mais disponível.', 'error')
        return redirect(url_for('admin.moderation_queue'))

    notes = request.form.get('notes', '').strip()
    # Qualquer decisão resolve as denúncias pendentes (tira a resposta da fila).
    db.resolve_comment_reports(comment_id)
    if action in ('approve', 'review'):
        msg = 'Resposta aprovada e mantida.' if action == 'approve' else 'Resposta revisada.'
    else:  # hide ou remove → oculta (comentário não tem soft-delete próprio)
        db.update_comment_visibility(comment_id, 0)
        msg = 'Resposta ocultada.' if action == 'hide' else 'Resposta removida.'

    db.log_moderation_action('comment', comment_id, action,
                             moderator_id=session.get('admin_user_id'),
                             moderator_username=session.get('admin_username'),
                             notes=notes)
    flash(msg, 'success')
    return redirect(url_for('admin.moderation_queue'))


@admin.route('/usuarios')
@admin_required
def users():
    """Gestão de cargos da equipe. Só admin atribui selos (Colaborador, CEO, Equipe)."""
    search = request.args.get('q', '').strip()
    users_list = db.get_all_users(search=search or None, limit=200)
    return render_template(
        'admin/users.html',
        users=users_list,
        search=search,
        role_order=ROLE_ORDER,
        role_labels=ROLE_LABELS,
    )


@admin.route('/usuarios/<int:user_id>/cargo', methods=['POST'])
@admin_required
def set_user_role(user_id):
    """Atribui um cargo a um usuário. Apenas admin (garantido por @admin_required)."""
    role = normalize_role(request.form.get('role'))

    # O selo é independente do acesso à moderação (is_admin), então mudar o
    # próprio cargo é seguro — é assim que o fundador define o selo de CEO.
    target = db.get_user_by_id(user_id)
    if not target:
        flash('Não encontramos esse usuário.', 'error')
        return redirect(url_for('admin.users'))

    if db.update_user_role(user_id, role):
        flash(f"Cargo de @{target['username']} atualizado para {ROLE_LABELS.get(role, role)}.", 'success')
    else:
        flash('Não conseguimos atualizar o cargo agora.', 'error')
    return redirect(url_for('admin.users', q=request.args.get('q', '')))
