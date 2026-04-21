from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, session
from datetime import datetime
import database as db
from utils.validation import LIMITS
from utils.sensitive_content import evaluate_post_content, RISK_MEDIUM, RISK_HIGH
from services.sensitive_response import build_sensitive_response

# Criação do Blueprint para as rotas de posts (desabafos)
posts = Blueprint('posts', __name__)

def _require_login_for_posts():
    if 'user_id' not in session:
        flash('Faça login para continuar.', 'error')
        return redirect(url_for('auth.login', next=request.path))
    return None

def _can_manage_post(post, current_user):
    if not post or not current_user:
        return False
    if post['user_id'] == current_user['id']:
        return True
    return bool(current_user['is_admin'] or current_user['role'] == 'admin')

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
    
    current_user = db.get_user_by_id(session['user_id']) if session.get('user_id') else None

    return render_template('feed.html', 
                          desabafos=desabafos, 
                          categorias=categorias_form,
                          categorias_disponiveis=categorias_disponiveis,
                          categoria_atual=categoria,
                          reacoes=reacoes,
                          page=page,
                          total_pages=total_pages,
                          current_user=current_user)

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
        if 'user_id' not in session:
            flash('Faça login ou crie uma conta para publicar um desabafo.', 'error')
            return redirect(url_for('auth.login', next=url_for('posts.feed')))

        conteudo = request.form.get('conteudo', '').strip()
        titulo = request.form.get('titulo', '').strip() or None
        categoria = request.form.get('categoria')
        visibility_mode = request.form.get('visibility_mode', 'anonymous').strip().lower()
        action = request.form.get('action', 'publish')
        post_status = 'draft' if action == 'draft' else 'published'
        
        if not conteudo or not categoria:
            flash('Por favor, preencha todos os campos.')
            return redirect(url_for('posts.feed'))
        if len(conteudo) < LIMITS["post_content_min"] or len(conteudo) > LIMITS["post_content_max"]:
            flash(f'O desabafo deve ter entre {LIMITS["post_content_min"]} e {LIMITS["post_content_max"]} caracteres.', 'error')
            return redirect(url_for('posts.feed'))
        if titulo and len(titulo) > LIMITS["post_title_max"]:
            flash(f'O título deve ter no máximo {LIMITS["post_title_max"]} caracteres.', 'error')
            return redirect(url_for('posts.feed'))

        if visibility_mode not in ('anonymous', 'profile'):
            flash('Visibilidade inválida para o post.', 'error')
            return redirect(url_for('posts.feed'))
        
        sensitivity = evaluate_post_content(conteudo)
        if post_status == 'published':
            if sensitivity['should_block']:
                flash('Detectamos sinais de risco imediato no texto. Edite a mensagem e, se puder, procure apoio no CVV (188).', 'error')
                return redirect(url_for('posts.feed'))

            if sensitivity['risk_level'] in (RISK_MEDIUM, RISK_HIGH):
                sensitive_ack = request.form.get('sensitive_ack') == '1'
                acknowledged_level = request.form.get('sensitive_risk')
                if not sensitive_ack or acknowledged_level != sensitivity['risk_level']:
                    flash('Antes de publicar, revise o aviso de cuidado exibido para o seu texto.', 'info')
                    return redirect(url_for('posts.feed'))

        # Cria o post no banco de dados (user_id vem apenas da sessão)
        try:
            post_id = db.create_post(
                mensagem=conteudo,
                categoria=categoria,
                user_id=session['user_id'],
                visibility_mode=visibility_mode,
                title=titulo,
                status=post_status,
            )
            if post_status == 'published' and sensitivity['risk_level'] == RISK_HIGH:
                db.log_sensitive_post(post_id=post_id, risk_level=RISK_HIGH)

        except ValueError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('posts.feed'))
        except Exception:
            flash('Não foi possível publicar seu desabafo. Tente novamente.', 'error')
            return redirect(url_for('posts.feed'))
        
        if post_status == 'draft':
            flash('Rascunho salvo com sucesso!', 'success')
            return redirect(url_for('posts.rascunhos'))
        flash('Desabafo publicado com sucesso!', 'success')
        return redirect(url_for('posts.feed'))
    
    return redirect(url_for('posts.feed'))
@posts.route('/analyze-content', methods=['POST'])
def analyze_content():
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    payload = request.get_json(silent=True) or {}
    text = (payload.get('text') or '').strip()
    analysis = evaluate_post_content(text)
    response = build_sensitive_response(analysis['risk_level'], should_block=analysis['should_block'])

    return jsonify({
        'risk_level': analysis['risk_level'],
        'should_block': analysis['should_block'],
        'response': response,
    })

@posts.route('/meus-posts', methods=['GET'])
def meus_posts():
    """Área privada com posts do usuário autenticado."""
    auth_redirect = _require_login_for_posts()
    if auth_redirect:
        return auth_redirect

    current_user = db.get_user_by_id(session['user_id'])
    if not current_user:
        session.clear()
        flash("Usuário não encontrado.", 'error')
        return redirect(url_for('auth.login'))

    page = request.args.get('page', 1, type=int)
    filter_mode = request.args.get('tipo', 'todos')
    visibility_mode = None
    status_filter = None
    if filter_mode == 'anonimos':
        visibility_mode = 'anonymous'
    elif filter_mode == 'publicados':
        visibility_mode = 'profile'
    elif filter_mode == 'rascunhos':
        status_filter = 'draft'

    per_page = 8
    offset = (page - 1) * per_page

    posts_list = db.get_posts_by_user(
        current_user['id'],
        limit=per_page,
        offset=offset,
        include_hidden=True,
        visibility_mode=visibility_mode,
        status=status_filter,
    )
    total_posts = db.get_post_count_by_user(
        current_user['id'],
        include_hidden=True,
        visibility_mode=visibility_mode,
        status=status_filter,
    )
    total_publicados = db.get_post_count_by_user(current_user['id'], include_hidden=True, visibility_mode='profile')
    total_anonimos = db.get_post_count_by_user(current_user['id'], include_hidden=True, visibility_mode='anonymous')
    total_rascunhos = db.get_post_count_by_user(current_user['id'], include_hidden=True, status='draft')
    total_pages = max(1, (total_posts + per_page - 1) // per_page)

    return render_template(
        'posts/meus_posts.html',
        meus_posts=posts_list,
        page=page,
        total_pages=total_pages,
        filter_mode=filter_mode,
        total_posts=total_posts,
        total_publicados=total_publicados,
        total_anonimos=total_anonimos,
        total_rascunhos=total_rascunhos,
    )


@posts.route('/rascunhos', methods=['GET'])
def rascunhos():
    auth_redirect = _require_login_for_posts()
    if auth_redirect:
        return auth_redirect
    page = request.args.get('page', 1, type=int)
    per_page = 8
    offset = (page - 1) * per_page
    user_id = session['user_id']
    drafts = db.get_posts_by_user(user_id, limit=per_page, offset=offset, include_hidden=True, status='draft')
    total = db.get_post_count_by_user(user_id, include_hidden=True, status='draft')
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template('posts/rascunhos.html', drafts=drafts, page=page, total_pages=total_pages, total_drafts=total)

@posts.route('/posts/<int:post_id>/editar', methods=['GET', 'POST'])
def editar_post(post_id):
    """Permite editar somente post próprio (ou admin)."""
    auth_redirect = _require_login_for_posts()
    if auth_redirect:
        return auth_redirect

    current_user = db.get_user_by_id(session['user_id'])
    post = db.get_post(post_id, include_hidden=True)

    if not _can_manage_post(post, current_user):
        flash('Você não tem permissão para editar este post.', 'error')
        return redirect(url_for('posts.meus_posts'))

    if request.method == 'GET':
        return render_template(
            'posts/editar.html',
            post=post,
            categorias=current_app.config['CATEGORIAS'],
        )

    conteudo = request.form.get('conteudo', '').strip()
    titulo = request.form.get('titulo', '').strip() or None
    categoria = request.form.get('categoria', '').strip()
    visibility_mode = request.form.get('visibility_mode', 'anonymous').strip().lower()
    status = request.form.get('status', post.get('status') or 'published')

    if not conteudo or not categoria:
        flash('Preencha conteúdo e categoria para editar o desabafo.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))
    if len(conteudo) < LIMITS["post_content_min"] or len(conteudo) > LIMITS["post_content_max"]:
        flash(f'O desabafo deve ter entre {LIMITS["post_content_min"]} e {LIMITS["post_content_max"]} caracteres.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))
    if titulo and len(titulo) > LIMITS["post_title_max"]:
        flash(f'O título deve ter no máximo {LIMITS["post_title_max"]} caracteres.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))

    if visibility_mode not in ('anonymous', 'profile'):
        flash('Visibilidade inválida para o post.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))

    updated = db.update_post(post_id, conteudo, categoria, visibility_mode, title=titulo, status=status)
    if not updated:
        flash('Não foi possível atualizar o post.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))

    flash('Post atualizado com sucesso!', 'success')
    return redirect(url_for('posts.meus_posts'))

@posts.route('/posts/<int:post_id>/excluir', methods=['POST'])
def excluir_post(post_id):
    """Permite excluir somente post próprio (ou admin)."""
    auth_redirect = _require_login_for_posts()
    if auth_redirect:
        return auth_redirect

    current_user = db.get_user_by_id(session['user_id'])
    post = db.get_post(post_id, include_hidden=True)

    if not _can_manage_post(post, current_user):
        flash('Você não tem permissão para excluir este post.', 'error')
        return redirect(url_for('posts.meus_posts'))

    deleted = db.delete_post(post_id)
    if not deleted:
        flash('Não foi possível excluir o post.', 'error')
        return redirect(url_for('posts.meus_posts'))

    flash('Post excluído com sucesso.', 'success')
    return redirect(url_for('posts.meus_posts'))

@posts.route('/categorias')
def get_categorias():
    """Rota para obter as categorias disponíveis (API)."""
    categorias = db.get_categories()
    return jsonify(categorias)