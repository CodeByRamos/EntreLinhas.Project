from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, flash
import database as db

# Criação do Blueprint para as rotas de autenticação
auth = Blueprint('auth', __name__)

@auth.route('/registro', methods=['GET', 'POST'])
def registro():
    """Página e lógica de registro de usuário."""
    if request.method == 'GET':
        return render_template('auth/registro.html')
    
    try:
        data = request.get_json() if request.is_json else request.form
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        nickname = data.get('nickname', '').strip()
        bio = data.get('bio', '').strip() or None
        email = data.get('email', '').strip() or None
        
        # Validações
        if not username or not password or not nickname:
            message = "Username, senha e apelido são obrigatórios."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html')
        
        if len(username) < 3:
            message = "Username deve ter pelo menos 3 caracteres."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html')
        
        if len(password) < 6:
            message = "Senha deve ter pelo menos 6 caracteres."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html')
        
        if password != confirm_password:
            message = "Senhas não coincidem."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/registro.html')
        
        # Criar usuário
        success, result = db.create_user(username, password, nickname, bio, email)
        
        if success:
            user_id = result
            # Fazer login automático
            user = db.get_user_by_id(user_id)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nickname'] = user['nickname']
            
            message = "Conta criada com sucesso!"
            if request.is_json:
                return jsonify({'success': True, 'message': message, 'redirect': url_for('main.feed')})
            flash(message, 'success')
            return redirect(url_for('main.feed'))
        else:
            if request.is_json:
                return jsonify({'success': False, 'message': result}), 400
            flash(result, 'error')
            return render_template('auth/registro.html')
            
    except Exception as e:
        message = "Erro interno do servidor."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 500
        flash(message, 'error')
        return render_template('auth/registro.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Página e lógica de login de usuário."""
    if request.method == 'GET':
        return render_template('auth/login.html')
    
    try:
        data = request.get_json() if request.is_json else request.form
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            message = "Username e senha são obrigatórios."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 400
            flash(message, 'error')
            return render_template('auth/login.html')
        
        # Autenticar usuário
        user = db.authenticate_user(username, password)
        
        if user:
            # Fazer login
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nickname'] = user['nickname']
            
            message = f"Bem-vindo de volta, {user['nickname']}!"
            if request.is_json:
                return jsonify({'success': True, 'message': message, 'redirect': url_for('main.feed')})
            flash(message, 'success')
            return redirect(url_for('main.feed'))
        else:
            message = "Username ou senha incorretos."
            if request.is_json:
                return jsonify({'success': False, 'message': message}), 401
            flash(message, 'error')
            return render_template('auth/login.html')
            
    except Exception as e:
        message = "Erro interno do servidor."
        if request.is_json:
            return jsonify({'success': False, 'message': message}), 500
        flash(message, 'error')
        return render_template('auth/login.html')

@auth.route('/logout')
def logout():
    """Logout do usuário."""
    session.clear()
    flash("Logout realizado com sucesso!", 'success')
    return redirect(url_for('main.home'))

@auth.route('/perfil')
def perfil():
    """Página de perfil do usuário."""
    if 'user_id' not in session:
        flash("É necessário estar logado para acessar o perfil.", 'error')
        return redirect(url_for('auth.login'))
    
    user = db.get_user_by_id(session['user_id'])
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

