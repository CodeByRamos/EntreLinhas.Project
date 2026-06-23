from flask import Blueprint, request, jsonify, current_app, session
import database as db
from utils.api_errors import api_error
from extensions import limiter

# Criação do Blueprint para as rotas de reações
reactions = Blueprint('reactions', __name__)

def _all_reaction_counts(post_id):
    counts = db.get_reaction_counts(post_id)
    return {r['valor']: counts.get(r['valor'], 0) for r in current_app.config['REACOES']}


@reactions.route('/api/reactions/<int:post_id>', methods=['GET'])
def get_reactions(post_id):
    """Contagem de reações de um post."""
    try:
        if not db.get_post(post_id):
            return jsonify({'error': 'Esse desabafo não está mais disponível.'}), 404
        return jsonify({'reactions': _all_reaction_counts(post_id)})
    except Exception as exc:
        current_app.logger.exception("REACTION_GET_ERROR post_id=%s", post_id)
        return jsonify(api_error("Não conseguimos carregar as reações agora.", exc, post_id=post_id)), 500


@reactions.route('/api/reactions/<int:post_id>', methods=['POST'])
@limiter.limit('60 per minute; 400 per hour')
def toggle_reaction(post_id):
    """Adiciona ou remove a reação de um usuário (toggle)."""
    # Exige login antes de qualquer validação (guest sempre recebe o convite de entrar).
    if 'user_id' not in session:
        return jsonify({'error': 'Entre ou crie uma conta para reagir.', 'auth_required': True}), 401

    data = request.get_json(silent=True) or {}
    if 'type' not in data:
        return jsonify({'error': 'Escolha uma reação antes de continuar.'}), 400

    reaction_type = data['type']
    user_id = str(session['user_id'])

    if not any(r['valor'] == reaction_type for r in current_app.config['REACOES']):
        return jsonify({'error': 'Essa reação não está disponível agora.'}), 400

    try:
        if not db.get_post(post_id):
            return jsonify({'error': 'Esse desabafo não está mais disponível.'}), 404

        if db.get_user_reaction(post_id, reaction_type, user_id):
            db.remove_reaction(post_id, reaction_type, user_id)
            action = 'removed'
        else:
            db.add_reaction(post_id, reaction_type, user_id)
            action = 'added'

        return jsonify({
            'reactions': _all_reaction_counts(post_id),
            'action': action,
            'reaction_type': reaction_type,
        })
    except Exception as exc:
        # NÃO mascara: loga o traceback completo e devolve o erro real em modo debug.
        current_app.logger.exception(
            "REACTION_ERROR post_id=%s type=%s user_id=%s", post_id, reaction_type, user_id
        )
        return jsonify(api_error(
            "Não conseguimos acolher sua reação agora.", exc,
            post_id=post_id, reaction_type=reaction_type, user_id=user_id,
        )), 500


@reactions.route('/api/echo/<int:post_id>', methods=['GET'])
def get_echo(post_id):
    post = db.get_post(post_id)
    if not post:
        return jsonify({'success': False, 'message': 'Esse desabafo não está mais disponível.'}), 404
    state = db.get_echo_state(post_id, session.get('user_id'))
    return jsonify({'success': True, 'echo': state})


@reactions.route('/api/echo/<int:post_id>', methods=['POST'])
@limiter.limit('60 per minute; 400 per hour')
def toggle_echo(post_id):
    if 'user_id' not in session:
        return jsonify({
            'success': False,
            'message': 'Entre na sua conta para ecoar um desabafo.'
        }), 401

    success, action, count, active = db.toggle_echo(post_id, session['user_id'])
    if not success and action == 'not_found':
        return jsonify({'success': False, 'message': 'Esse desabafo não está mais disponível.'}), 404
    if not success:
        return jsonify({'success': False, 'message': 'Não conseguimos registrar seu eco agora.'}), 500

    message = 'Seu eco foi registrado.' if active else 'Seu eco foi recolhido.'
    return jsonify({
        'success': True,
        'action': action,
        'count': count,
        'active': active,
        'message': message,
    })
