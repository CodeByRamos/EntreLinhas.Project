from flask import Blueprint, request, jsonify
import database as db
from utils.validation import LIMITS
from utils.sensitive_content import evaluate_post_content

# Criação do Blueprint para as rotas de comentários
comments = Blueprint('comments', __name__)

@comments.route('/api/comments/<int:post_id>', methods=['GET'])
def get_comments(post_id):
    """API para obter comentários de um post específico."""
    try:
        # Verifica se o post existe
        post = db.get_post(post_id)
        if not post:
            return jsonify({'error': 'Esse desabafo não está mais disponível.'}), 404
        
        comments_list = db.get_comments(post_id)
        
        # Converte os objetos Row para dicionários
        comments_data = []
        for comment in comments_list:
            comments_data.append({
                'id': comment['id'],
                'text': comment['mensagem'],
                'date': comment['data_comentario']
            })
        
        return jsonify({'comments': comments_data})
    except Exception as e:
        print(f"Erro ao carregar comentários do post {post_id}: {e}")
        return jsonify({'error': 'Não conseguimos carregar as respostas agora.'}), 500

@comments.route('/api/comments/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    """API para adicionar um comentário a um post."""
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
        
        # Cria o comentário no banco de dados
        comment_id = db.create_comment(post_id, comment_text)
        
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
            comment_data = {
                'id': new_comment['id'],
                'text': new_comment['mensagem'],
                'date': new_comment['data_comentario']
            }
            return jsonify({'comment': comment_data})
        else:
            return jsonify({'error': 'Sua resposta foi enviada, mas não conseguimos mostrá-la agora.'}), 500
            
    except Exception as e:
        print(f"Erro ao adicionar comentário ao post {post_id}: {e}")
        return jsonify({'error': 'Não conseguimos enviar sua resposta agora.'}), 500
