from urllib.parse import urljoin, urlparse
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, flash
import database as db
from services.auth_service import (
    register_user,
    authenticate_user as authenticate_user_service,
    get_current_user,
    is_valid_email,
)

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
        bio = data.get('bio', '').strip() or None
        email = data.get('email', '').strip()
        
        # Validações
        if not email or not password:
            message = "E-mail e senha são obrigatórios."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html', next_url=request.form.get('next', ''))

        if username and len(username) < 3:
            message = "Username deve ter pelo menos 3 caracteres."
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

        if len(password) < 6:
            message = "Senha deve ter pelo menos 6 caracteres."
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
        
        # Criar usuário
        success, payload = register_user(username, password, nickname, bio, email)
        
        if success:
            # Fazer login automático
            user = payload['user']
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nickname'] = user['nickname']
            session.permanent = True
            
            message = "Conta criada com sucesso!"
            redirect_target = _safe_redirect_target()
            if request.is_json:
                return jsonify({'success': True, 'message': message, 'redirect': redirect_target})
            flash(message, 'success')
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
        bio = data.get('bio', '').strip() or None
        email = data.get('email', '').strip() or None
        
        if not nickname:
            message = "Apelido é obrigatório."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/editar_perfil.html', user=user)
        
        # Atualizar usuário
        success, message = db.update_user(user['id'], nickname, bio, email)
        
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
        
        if len(new_password) < 6:
            message = "Nova senha deve ter pelo menos 6 caracteres."
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