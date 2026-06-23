from flask import Blueprint, request, jsonify, current_app, session
import database as db
from utils.validation import LIMITS
from utils.sensitive_content import evaluate_post_content
from utils.api_errors import api_error
from utils.roles import get_role_badge

# Criação do Blueprint para as rotas de comentários
comments = Blueprint('comments', __name__)


def _serialize_comment(comment):
    """Monta o JSON de um comentário, com selo de cargo só para a equipe.

    Respostas de usuários comuns continuam anônimas (sem nome, sem selo).
    """
    data = {
        'id': comment['id'],
        'text': comment['mensagem'],
        'date': comment['data_comentario'],
    }
    role = comment['author_role'] if 'author_role' in comment.keys() else None
    badge = get_role_badge(role)
    if badge:
        data['author_name'] = (
            comment['author_display_name']
            or comment['author_username']
            or 'Equipe EntreLinhas'
        )
        data['author_role'] = badge['slug']
        data['author_role_label'] = badge['label']
    return data

@comments.route('/api/comments/<int:post_id>', methods=['GET'])
def get_comments(post_id):
    """API para obter comentários de um post específico."""
    try:
        # Verifica se o post existe
        post = db.get_post(post_id)
        if not post:
            return jsonify({'error': 'Esse desabafo não está mais disponível.'}), 404
        
        comments_list = db.get_comments(post_id)

        # Converte os objetos Row para dicionários (com selo de cargo da equipe)
        comments_data = [_serialize_comment(comment) for comment in comments_list]

        return jsonify({'comments': comments_data})
    except Exception as exc:
        current_app.logger.exception("COMMENT_LOAD_ERROR post_id=%s", post_id)
        return jsonify(api_error("Não conseguimos carregar as respostas agora.", exc, post_id=post_id)), 500

@comments.route('/api/comments/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    """API para adicionar um comentário a um post. Exige login (validação no backend)."""
    if 'user_id' not in session:
        return jsonify({'error': 'Entre ou crie uma conta para responder com cuidado.', 'auth_required': True}), 401
    try:
        data = request.json

        if not data or 'text' not in data or not data['text'].strip():
            return jsonify({'error': 'Escreva uma resposta antes de enviar.'}), 400
        
        comment_text = data['text'].strip()
        if len(comment_text) < LIMITS["comment_content_min"] or len(comment_text) > LIMITS["comment_content_max"]:
            return jsonify({'error': f'Sua resposta precisa ter entre {LIMITS["comment_content_min"]} e {LIMITS["comment_content_max"]} caracteres.'}), 400

        # Discurso de ódio com ataque direto não pode ser enviado (mesmo crivo dos posts;
        # respeita quem relata a própria experiência, bloqueia ofensa a terceiros).
        if evaluate_post_content(comment_text).get('block_publication'):
            return jsonify({'error': 'Essa resposta traz uma ofensa que fere outras pessoas e não pode ser enviada assim. Reescreva com respeito para continuar.'}), 400

        # Verifica se o post existe
        post = db.get_post(post_id)
        if not post:
            return jsonify({'error': 'Esse desabafo não está mais disponível.'}), 404
        
        # Cria o comentário no banco de dados (associado ao autor logado)
        comment_id = db.create_comment(post_id, comment_text, user_id=session['user_id'])
        
        if not comment_id:
            return jsonify({'error': 'Não conseguimos guardar sua resposta agora.'}), 500
        
        # Obtém o comentário recém-criado para retornar
        new_comment = db.get_comment_by_id(comment_id, include_hidden=True)
        
        if new_comment:
            if 'user_id' in post.keys() and post['user_id']:
                db.create_notification(
                    user_id=post['user_id'],
                    notification_type='post_reply',
                    title='Nova resposta no seu post',
                    message='Alguém respondeu um desabafo seu. Entre para acompanhar.',
                    reference_id=post_id,
                )
            return jsonify({'comment': _serialize_comment(new_comment)})
        else:
            return jsonify({'error': 'Sua resposta foi enviada, mas não conseguimos mostrá-la agora.'}), 500
            
    except Exception as exc:
        # NÃO mascara: traceback completo no log + erro real em modo debug.
        current_app.logger.exception("COMMENT_ERROR post_id=%s", post_id)
        return jsonify(api_error("Não conseguimos enviar sua resposta agora.", exc, post_id=post_id)), 500
