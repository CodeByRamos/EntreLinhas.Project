from urllib.parse import urljoin, urlparse
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, flash
import database as db
from services.auth_service import (
    register_user,
    authenticate_user as authenticate_user_service,
    get_current_user,
    is_valid_email,
)
from services.email_service import send_password_reset_email, send_email_verification
from utils.validation import LIMITS, is_valid_username

# Criação do Blueprint para as rotas de autenticação
auth = Blueprint('auth', __name__)


def _is_safe_redirect_url(target):
    """Valida redirecionamentos para evitar open redirect."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def _safe_redirect_target(default_endpoint="posts.feed"):
    """Retorna destino de redirecionamento seguro baseado em next."""
    next_url = request.args.get("next") or request.form.get("next")
    if next_url and _is_safe_redirect_url(next_url):
        return next_url
    return url_for(default_endpoint)

@auth.route('/registro', methods=['GET', 'POST'])
def registro():
    """Página e lógica de registro de usuário."""
    if request.method == 'GET':
        return render_template('auth/registro.html', next_url=request.args.get('next', ''))
    
    try:
        data = request.get_json() if request.is_json else request.form
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        nickname = data.get('nickname', '').strip()
        display_name = data.get('display_name', '').strip()
        bio = data.get('bio', '').strip() or None
        avatar_url = data.get('avatar_url', '').strip() or None
        email = data.get('email', '').strip()
        default_visibility_mode = data.get('default_visibility_mode', 'anonymous').strip().lower()
        
        # Validações
        if not email or not password:
            message = "E-mail e senha são obrigatórios."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html', next_url=request.form.get('next', ''))

        if username and not is_valid_username(username):
            message = "Username inválido. Use 3 a 30 caracteres (letras, números, _ ou .)."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html', next_url=request.form.get('next', ''))

        if not is_valid_email(email):
            message = "Informe um e-mail válido."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html', next_url=request.form.get('next', ''))

        if len(password) < LIMITS["password_min"] or len(password) > LIMITS["password_max"]:
            message = f"Senha deve ter entre {LIMITS['password_min']} e {LIMITS['password_max']} caracteres."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html', next_url=request.form.get('next', ''))
        
        if password != confirm_password:
            message = "Senhas não coincidem."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html', next_url=request.form.get('next', ''))
        
        if bio and len(bio) > LIMITS["bio_max"]:
            message = f"Bio deve ter no máximo {LIMITS['bio_max']} caracteres."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html', next_url=request.form.get('next', ''))

        if default_visibility_mode not in ('anonymous', 'profile'):
            default_visibility_mode = 'anonymous'

        if not display_name:
            display_name = nickname or username or email.split('@')[0]

        # Criar usuário
        success, payload = register_user(
            username,
            password,
            nickname,
            bio,
            email,
            display_name=display_name,
            avatar_url=avatar_url,
            default_visibility_mode=default_visibility_mode,
        )
        
        if success:
            # Fazer login automático
            user = payload['user']
            if user.get('email'):
                token = db.create_email_verification_token(user['id'])
                delivery = send_email_verification(user['email'], token)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nickname'] = user['nickname']
            session.permanent = True
            
            message = "Conta criada com sucesso!"
            redirect_target = _safe_redirect_target()
            if request.is_json:
                return jsonify({'success': True, 'message': message, 'redirect': redirect_target})
            flash(message, 'success')
            if user.get('email') and delivery.get('preview_url'):
                flash(f"Ambiente local: confirme seu e-mail em {delivery['preview_url']}", 'success')
            return redirect(redirect_target)
        else:
            if request.is_json:
                return jsonify({'success': False, 'message': payload['message']}), 400
            flash(payload['message'], 'error')
            return render_template('auth/registro.html', next_url=request.form.get('next', ''))
            
    except Exception as e:
        message = "Erro interno do servidor."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 500
        flash(message, 'error')
        return render_template('auth/registro.html', next_url=request.form.get('next', ''))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Página e lógica de login de usuário."""
    if request.method == 'GET':
        return render_template('auth/login.html', next_url=request.args.get('next', ''))
    
    try:
        data = request.get_json() if request.is_json else request.form
        
        email = data.get('email', '').strip()
        password = data.get('password', '')

        if not email or not password:
            message = "E-mail e senha são obrigatórios."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/login.html', next_url=request.form.get('next', ''))

        if not is_valid_email(email):
            message = "Informe um e-mail válido."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/login.html', next_url=request.form.get('next', ''))

        # Autenticar usuário
        success, payload = authenticate_user_service(email, password)
        
        if success:
            user = payload['user']
            # Fazer login
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nickname'] = user['nickname']
            session.permanent = True

            message = f"Bem-vindo de volta, {user['nickname']}!"
            redirect_target = _safe_redirect_target()
            if request.is_json:
                return jsonify({'success': True, 'message': message, 'redirect': redirect_target})
            flash(message, 'success')
            return redirect(redirect_target)
        else:
            message = payload['message']
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 401
            flash(message, 'error')
            return render_template('auth/login.html', next_url=request.form.get('next', ''))
            
    except Exception as e:
        message = "Erro interno do servidor."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 500
        flash(message, 'error')
        return render_template('auth/login.html', next_url=request.form.get('next', ''))

@auth.route('/logout', methods=['POST'])
def logout():
    """Logout do usuário."""
    session.clear()
    flash("Logout realizado com sucesso!", 'success')
    return redirect(_safe_redirect_target(default_endpoint='main.home'))

@auth.route('/perfil')
def perfil():
    """Página de perfil do usuário."""
    if 'user_id' not in session:
        flash("É necessário estar logado para acessar o perfil.", 'error')
        return redirect(url_for('auth.login'))
    
    user = get_current_user(session)
    if not user:
        session.clear()
        flash("Usuário não encontrado.", 'error')
        return redirect(url_for('auth.login'))
    
    stats = db.get_user_stats(user['id'])
    
    return render_template('auth/perfil.html', user=user, stats=stats)

@auth.route('/perfil/editar', methods=['GET', 'POST'])
def editar_perfil():
    """Página e lógica para editar perfil do usuário."""
    if 'user_id' not in session:
        flash("É necessário estar logado para editar o perfil.", 'error')
        return redirect(url_for('auth.login'))
    
    user = db.get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        flash("Usuário não encontrado.", 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'GET':
        return render_template('auth/editar_perfil.html', user=user)
    
    try:
        data = request.get_json() if request.is_json else request.form
        
        nickname = data.get('nickname', '').strip()
        display_name = data.get('display_name', '').strip()
        bio = data.get('bio', '').strip() or None
        avatar_url = data.get('avatar_url', '').strip() or None
        email = data.get('email', '').strip() or None
        default_visibility_mode = data.get('default_visibility_mode', 'anonymous').strip().lower()
        
        if not nickname:
            message = "Apelido é obrigatório."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/editar_perfil.html', user=user)
        
        if not display_name:
            message = "Nome público é obrigatório."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/editar_perfil.html', user=user)

        if bio and len(bio) > LIMITS["bio_max"]:
            message = f"Bio deve ter no máximo {LIMITS['bio_max']} caracteres."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/editar_perfil.html', user=user)
        if email and not is_valid_email(email):
            message = "Informe um e-mail válido."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/editar_perfil.html', user=user)

        if default_visibility_mode not in ('anonymous', 'profile'):
            default_visibility_mode = 'anonymous'

        # Atualizar usuário
        success, message = db.update_user(
            user['id'],
            nickname=nickname,
            bio=bio,
            email=email,
            display_name=display_name,
            avatar_url=avatar_url,
            default_visibility_mode=default_visibility_mode,
        )
        
        if success:
            # Atualizar sessão
            session['nickname'] = nickname
            
            if request.is_json:
                return jsonify({'success': True, 'message': message, 'redirect': url_for('auth.perfil')})
            flash(message, 'success')
            return redirect(url_for('auth.perfil'))
        else:
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/editar_perfil.html', user=user)
            
    except Exception as e:
        message = "Erro interno do servidor."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 500
        flash(message, 'error')
        return render_template('auth/editar_perfil.html', user=user)

@auth.route('/perfil/alterar-senha', methods=['GET', 'POST'])
def alterar_senha():
    """Página e lógica para alterar senha do usuário."""
    if 'user_id' not in session:
        flash("É necessário estar logado para alterar a senha.", 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'GET':
        return render_template('auth/alterar_senha.html')
    
    try:
        data = request.get_json() if request.is_json else request.form
        
        old_password = data.get('old_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not old_password or not new_password:
            message = "Senha atual e nova senha são obrigatórias."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/alterar_senha.html')
        
        if len(new_password) < LIMITS["password_min"] or len(new_password) > LIMITS["password_max"]:
            message = f"Nova senha deve ter entre {LIMITS['password_min']} e {LIMITS['password_max']} caracteres."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/alterar_senha.html')
        
        if new_password != confirm_password:
            message = "Senhas não coincidem."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/alterar_senha.html')
        
        if old_password == new_password:
            message = "A nova senha deve ser diferente da senha atual."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/alterar_senha.html')
        
        # Alterar senha
        success, message = db.change_password(session['user_id'], old_password, new_password)
        
        if success:
            if request.is_json:
                return jsonify({'success': True, 'message': message, 'redirect': url_for('auth.perfil')})
            flash(message, 'success')
            return redirect(url_for('auth.perfil'))
        else:
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/alterar_senha.html')
            
    except Exception as e:
        message = "Erro interno do servidor."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 500
        flash(message, 'error')
        return render_template('auth/alterar_senha.html')


@auth.route('/esqueci-senha', methods=['GET', 'POST'])
def esqueci_senha():
    if request.method == 'GET':
        return render_template('auth/esqueci_senha.html')

    data = request.get_json() if request.is_json else request.form
    email = (data.get('email') or '').strip()
    if not email or not is_valid_email(email):
        message = "Informe um e-mail válido."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return render_template('auth/esqueci_senha.html')

    user = db.get_user_by_email(email)
    preview_url = None
    if user:
        token = db.create_password_reset_token(user['id'])
        delivery = send_password_reset_email(email, token)
        preview_url = delivery.get('preview_url')

    message = "Se houver uma conta com este e-mail, enviamos instruções para redefinir sua senha."
    if request.is_json:
        payload = {'success': True, 'message': message}
        if preview_url:
            payload['preview_url'] = preview_url
        return jsonify(payload)
    flash(message, 'success')
    if preview_url:
        flash(f"Ambiente local: link de redefinição {preview_url}", 'success')
    return redirect(url_for('auth.login'))


@auth.route('/redefinir-senha', methods=['GET', 'POST'])
def redefinir_senha():
    token = (request.args.get('token') or request.form.get('token') or '').strip()
    if request.method == 'GET':
        return render_template('auth/redefinir_senha.html', token=token)

    data = request.get_json() if request.is_json else request.form
    token = (data.get('token') or token).strip()
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')

    if not token:
        message = "Token de redefinição é obrigatório."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return render_template('auth/redefinir_senha.html', token=token)
    if len(token) < LIMITS["token_min"] or len(token) > LIMITS["token_max"]:
        message = "Token inválido."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return render_template('auth/redefinir_senha.html', token=token)
    if len(new_password) < LIMITS["password_min"] or len(new_password) > LIMITS["password_max"]:
        message = f"Senha deve ter entre {LIMITS['password_min']} e {LIMITS['password_max']} caracteres."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return render_template('auth/redefinir_senha.html', token=token)
    if new_password != confirm_password:
        message = "As senhas informadas não coincidem."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return render_template('auth/redefinir_senha.html', token=token)

    valid, token_message, user_id = db.consume_password_reset_token(token)
    if not valid:
        if request.is_json:
            return jsonify({'success': False, 'message': token_message}), 400
        flash(token_message, 'error')
        return render_template('auth/redefinir_senha.html', token=token)

    success, update_message = db.set_new_password(user_id, new_password)
    category = 'success' if success else 'error'
    if request.is_json:
        return jsonify({'success': success, 'message': update_message}), (200 if success else 400)
    flash(update_message, category)
    return redirect(url_for('auth.login'))


@auth.route('/verificar-email', methods=['GET'])
def verificar_email():
    token = (request.args.get('token') or '').strip()
    if not token:
        flash("Token de verificação ausente.", 'error')
        return redirect(url_for('auth.perfil') if session.get('user_id') else url_for('auth.login'))
    if len(token) < LIMITS["token_min"] or len(token) > LIMITS["token_max"]:
        flash("Token inválido.", 'error')
        return redirect(url_for('auth.perfil') if session.get('user_id') else url_for('auth.login'))

    success, message = db.verify_email_with_token(token)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('auth.perfil') if session.get('user_id') else url_for('auth.login'))


@auth.route('/verificacao-email/reenviar', methods=['POST'])
def reenviar_verificacao_email():
    if 'user_id' not in session:
        flash("É necessário estar logado.", 'error')
        return redirect(url_for('auth.login'))

    user = db.get_user_by_id(session['user_id'])
    if not user or not user['email']:
        flash("Cadastre um e-mail válido no perfil para verificar sua conta.", 'error')
        return redirect(url_for('auth.editar_perfil'))
    if user['is_verified']:
        flash("Sua conta já está verificada.", 'success')
        return redirect(url_for('auth.perfil'))

    token = db.create_email_verification_token(user['id'])
    delivery = send_email_verification(user['email'], token)
    flash("Link de verificação preparado.", 'success')
    if delivery.get('preview_url'):
        flash(f"Ambiente local: link de verificação {delivery['preview_url']}", 'success')
    return redirect(url_for('auth.perfil'))

# Função auxiliar para verificar se o usuário está logado
def login_required(f):
    """Decorator para rotas que requerem login."""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Login necessário.'}), 401
            flash("É necessário estar logado para acessar esta página.", 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function