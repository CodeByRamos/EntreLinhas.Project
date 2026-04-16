from flask import Blueprint, redirect, url_for, flash, session

# Criação do Blueprint para as rotas de perfil
profile = Blueprint('profile', __name__)

@profile.route('/perfil/criar', methods=['GET', 'POST'])
def criar_perfil():
    """Fluxo legado desativado: perfil temporário sem conta."""
    flash('Perfis temporários foram desativados. Entre com sua conta.', 'error')
    return redirect(url_for('auth.login', next=url_for('auth.perfil')))

@profile.route('/perfil-legado', methods=['GET'])
def ver_perfil():
    """Redireciona o perfil antigo para perfil autenticado."""
    if 'user_id' not in session:
        flash('Entre na sua conta para acessar o perfil.', 'error')
        return redirect(url_for('auth.login', next=url_for('auth.perfil')))
    return redirect(url_for('auth.perfil'))

@profile.route('/perfil/editar', methods=['GET', 'POST'])
def editar_perfil():
    """Fluxo legado desativado: usar perfil autenticado."""
    flash('Use o perfil da conta para editar seus dados.', 'error')
    return redirect(url_for('auth.editar_perfil'))

@profile.route('/perfil/sair', methods=['GET'])
def sair_perfil():
    """Limpeza de sessão legada de perfil temporário."""
    session.pop('profile_token', None)
    return redirect(url_for('auth.login'))

@profile.route('/perfil/posts', methods=['GET'])
def posts_perfil():
    """Fluxo legado desativado: usar perfil autenticado."""
    return redirect(url_for('auth.perfil'))

@profile.route('/perfil/comentarios', methods=['GET'])
def comentarios_perfil():
    """Fluxo legado desativado: usar perfil autenticado."""
    return redirect(url_for('auth.perfil'))