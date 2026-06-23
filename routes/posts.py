from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, session
from datetime import datetime
import database as db
from utils.validation import LIMITS
from utils.sensitive_content import evaluate_post_content, RISK_MEDIUM, RISK_HIGH
from services.sensitive_response import build_content_response, resolve_content_gate
from utils.mood_styles import EMOTIONAL_TAG_LABELS, dominant_mood, is_valid_emotional_tag, normalize_emotional_tag
from utils.safe_logging import log_exception
from extensions import limiter

# Criação do Blueprint para as rotas de posts (desabafos)
posts = Blueprint('posts', __name__)

def _require_login_for_posts():
    if 'user_id' not in session:
        flash('Entre na sua conta para continuar.', 'error')
        return redirect(url_for('auth.login', next=request.path))
    return None

def _can_manage_post(post, current_user):
    if not post or not current_user:
        return False
    if post['user_id'] == current_user['id']:
        return True
    # Poder de moderação vem APENAS de is_admin. O cargo (role) é só selo
    # cosmético — não concede direito de editar/excluir posts de terceiros.
    return bool(current_user['is_admin'])

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
    emotional_tags = current_app.config.get('TAGS_EMOCIONAIS', [])
    reacoes = current_app.config['REACOES']
    daily_text = db.get_daily_text()
    feed_mood = dominant_mood(desabafos)
    
    current_user = db.get_user_by_id(session['user_id']) if session.get('user_id') else None

    return render_template('feed.html', 
                          desabafos=desabafos, 
                          categorias=categorias_form,
                          emotional_tags=emotional_tags,
                          emotional_tag_labels=EMOTIONAL_TAG_LABELS,
                          daily_text=daily_text,
                          feed_mood=feed_mood,
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
@limiter.limit('20 per minute; 120 per hour')
def enviar():
    """Rota para enviar um novo desabafo."""
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('Entre ou crie uma conta para publicar seu desabafo.', 'error')
            return redirect(url_for('auth.login', next=url_for('posts.feed')))

        conteudo = request.form.get('conteudo', '').strip()
        titulo = request.form.get('titulo', '').strip() or None
        categoria = request.form.get('categoria')
        emotional_tag = normalize_emotional_tag(request.form.get('emotional_tag'))
        visibility_mode = request.form.get('visibility_mode', 'anonymous').strip().lower()
        action = request.form.get('action', 'publish')
        post_status = 'draft' if action == 'draft' else 'published'
        
        valid_categories = {item['valor'] for item in current_app.config.get('CATEGORIAS', [])}
        if not conteudo or not categoria:
            flash('Esse campo precisa ser preenchido.', 'error')
            return redirect(url_for('posts.feed'))
        if categoria not in valid_categories:
            flash('Escolha um assunto da lista para publicar com segurança.', 'error')
            return redirect(url_for('posts.feed'))
        if not is_valid_emotional_tag(emotional_tag):
            flash('Escolha uma emoção da lista para situar seu desabafo.', 'error')
            return redirect(url_for('posts.feed'))
        if len(conteudo) < LIMITS["post_content_min"] or len(conteudo) > LIMITS["post_content_max"]:
            flash(f'O desabafo deve ter entre {LIMITS["post_content_min"]} e {LIMITS["post_content_max"]} caracteres.', 'error')
            return redirect(url_for('posts.feed'))
        if titulo and len(titulo) > LIMITS["post_title_max"]:
            flash(f'O título deve ter no máximo {LIMITS["post_title_max"]} caracteres.', 'error')
            return redirect(url_for('posts.feed'))

        if visibility_mode not in ('anonymous', 'profile'):
            flash('Não conseguimos entender como exibir esse desabafo.', 'error')
            return redirect(url_for('posts.feed'))
        
        sensitivity = evaluate_post_content(f"{titulo} {conteudo}" if titulo else conteudo)
        is_sensitive = sensitivity['risk_level'] in (RISK_MEDIUM, RISK_HIGH)
        is_hate = sensitivity.get('is_hate_speech', False)
        if post_status == 'published':
            # Discurso de ódio com ataque direto: barrado no servidor, sempre.
            if sensitivity.get('block_publication'):
                flash(
                    'Esse desabafo traz uma ofensa que fere outras pessoas e não pode ser '
                    'publicado assim. O EntreLinhas é pra desabafar a sua dor, não pra atacar '
                    'ninguém. Edite o texto e tente de novo.',
                    'error',
                )
                return redirect(url_for('posts.feed'))
            # Risco emocional ou xingamento isolado: exige confirmação consciente.
            needs_ack = is_sensitive or sensitivity.get('hate_action') == 'warn'
            if needs_ack and request.form.get('sensitive_ack') != '1':
                flash('Antes de publicar, leia o aviso de cuidado para esse texto.', 'info')
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
                emotional_tag=emotional_tag,
                sensitive_flag=is_sensitive or is_hate,
            )
            if post_status == 'published' and sensitivity['risk_level'] == RISK_HIGH:
                db.log_sensitive_post(post_id=post_id, risk_level=RISK_HIGH)

        except ValueError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('posts.feed'))
        except Exception as exc:
            log_exception(
                current_app.logger,
                "posts.create",
                "create_post",
                exc,
                user_id=session.get('user_id'),
                table="posts",
                operation="insert",
                status=post_status,
                emotional_tag=emotional_tag,
                category=categoria,
            )
            message = 'Não conseguimos publicar seu desabafo agora. Tente novamente em instantes.'
            if current_app.config.get("ENVIRONMENT") == "development":
                message = f"{message} Detalhe local: {exc.__class__.__name__}: {exc}"
            flash(message, 'error')
            return redirect(url_for('posts.feed'))
        
        if post_status == 'draft':
            flash('Seu rascunho ficou guardado.', 'success')
            return redirect(url_for('posts.rascunhos'))
        if is_sensitive:
            flash('Seu desabafo encontrou um lugar. E existe ajuda real disponível se essa dor estiver pesada demais.', 'success')
        else:
            flash('Seu desabafo encontrou um lugar.', 'success')
        return redirect(url_for('posts.feed'))
    
    return redirect(url_for('posts.feed'))
@posts.route('/analyze-content', methods=['POST'])
def analyze_content():
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    payload = request.get_json(silent=True) or {}
    text = (payload.get('text') or '').strip()
    analysis = evaluate_post_content(text)
    response = build_content_response(analysis)
    gate = resolve_content_gate(analysis)

    return jsonify({
        'risk_level': analysis['risk_level'],
        'should_block': analysis['should_block'],
        'block_publication': analysis.get('block_publication', False),
        'hate_action': analysis.get('hate_action', 'none'),
        'gate': gate,
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
        flash("Não encontramos sua conta. Entre novamente para continuar.", 'error')
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


@posts.route('/ecos', methods=['GET'])
def ecos():
    """Mostra os desabafos que o usuário ecoou."""
    auth_redirect = _require_login_for_posts()
    if auth_redirect:
        return auth_redirect

    current_user = db.get_user_by_id(session['user_id'])
    if not current_user:
        session.clear()
        flash("Entre novamente para ver seus ecos.", 'error')
        return redirect(url_for('auth.login'))

    page = request.args.get('page', 1, type=int)
    per_page = 8
    offset = (page - 1) * per_page
    echoed_posts = db.get_echoed_posts_by_user(current_user['id'], limit=per_page, offset=offset)
    total_echoes = db.get_echoed_post_count_by_user(current_user['id'])
    total_pages = max(1, (total_echoes + per_page - 1) // per_page)

    return render_template(
        'posts/ecos.html',
        echoed_posts=echoed_posts,
        page=page,
        total_pages=total_pages,
        total_echoes=total_echoes,
        emotional_tag_labels=EMOTIONAL_TAG_LABELS,
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
        flash('Você só pode editar os desabafos que escreveu.', 'error')
        return redirect(url_for('posts.meus_posts'))

    if request.method == 'GET':
        return render_template(
            'posts/editar.html',
            post=post,
            categorias=current_app.config['CATEGORIAS'],
            emotional_tags=current_app.config.get('TAGS_EMOCIONAIS', []),
        )

    conteudo = request.form.get('conteudo', '').strip()
    titulo = request.form.get('titulo', '').strip() or None
    categoria = request.form.get('categoria', '').strip()
    emotional_tag = normalize_emotional_tag(request.form.get('emotional_tag'))
    visibility_mode = request.form.get('visibility_mode', 'anonymous').strip().lower()
    status = request.form.get('status', post['status'] if 'status' in post.keys() else 'published')

    if not conteudo or not categoria:
        flash('Preencha o texto e o assunto para salvar o desabafo.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))
    if not is_valid_emotional_tag(emotional_tag):
        flash('Escolha uma emoção da lista para situar seu desabafo.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))
    if len(conteudo) < LIMITS["post_content_min"] or len(conteudo) > LIMITS["post_content_max"]:
        flash(f'O desabafo deve ter entre {LIMITS["post_content_min"]} e {LIMITS["post_content_max"]} caracteres.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))
    if titulo and len(titulo) > LIMITS["post_title_max"]:
        flash(f'O título deve ter no máximo {LIMITS["post_title_max"]} caracteres.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))

    if visibility_mode not in ('anonymous', 'profile'):
        flash('Não conseguimos entender como exibir esse desabafo.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))

    sensitivity = evaluate_post_content(f"{titulo} {conteudo}" if titulo else conteudo)
    if status == 'published' and sensitivity.get('block_publication'):
        flash(
            'Esse desabafo traz uma ofensa que fere outras pessoas e não pode ser publicado '
            'assim. O EntreLinhas é pra desabafar a sua dor, não pra atacar ninguém. '
            'Edite o texto e tente de novo.',
            'error',
        )
        return redirect(url_for('posts.editar_post', post_id=post_id))

    flag_sensitive = (
        sensitivity['risk_level'] in (RISK_MEDIUM, RISK_HIGH)
        or sensitivity.get('is_hate_speech', False)
    )
    updated = db.update_post(
        post_id,
        conteudo,
        categoria,
        visibility_mode,
        title=titulo,
        status=status,
        emotional_tag=emotional_tag,
        sensitive_flag=flag_sensitive,
    )
    if not updated:
        flash('Não conseguimos atualizar seu desabafo agora.', 'error')
        return redirect(url_for('posts.editar_post', post_id=post_id))

    flash('Seu desabafo foi atualizado.', 'success')
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
        flash('Você só pode retirar os desabafos que escreveu.', 'error')
        return redirect(url_for('posts.meus_posts'))

    deleted = db.delete_post(post_id)
    if not deleted:
        flash('Não conseguimos retirar esse desabafo agora.', 'error')
        return redirect(url_for('posts.meus_posts'))

    flash('Seu desabafo foi retirado.', 'success')
    return redirect(url_for('posts.meus_posts'))

@posts.route('/categorias')
def get_categorias():
    """Rota para obter as categorias disponíveis (API)."""
    categorias = db.get_categories()
    return jsonify(categorias)
