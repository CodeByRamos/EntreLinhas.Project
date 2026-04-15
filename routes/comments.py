from flask import Blueprint, request, jsonify
import database as db

# Criação do Blueprint para as rotas de comentários
comments = Blueprint('comments', __name__)

@comments.route('/api/comments/<int:post_id>', methods=['GET'])
def get_comments(post_id):
    """API para obter comentários de um post específico."""
    try:
        # Verifica se o post existe
        post = db.get_post(post_id)
        if not post:
            return jsonify({'error': 'Post não encontrado'}), 404
        
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
        return jsonify({'error': 'Erro interno do servidor'}), 500

@comments.route('/api/comments/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    """API para adicionar um comentário a um post."""
    try:
        data = request.json
        
        if not data or 'text' not in data or not data['text'].strip():
            return jsonify({'error': 'O comentário não pode estar vazio'}), 400
        
        comment_text = data['text'].strip()
        
        # Verifica se o post existe
        post = db.get_post(post_id)
        if not post:
            return jsonify({'error': 'Post não encontrado'}), 404
        
        # Cria o comentário no banco de dados
        comment_id = db.create_comment(post_id, comment_text)
        
        if not comment_id:
            return jsonify({'error': 'Erro ao criar comentário'}), 500
        
        # Obtém o comentário recém-criado para retornar
        new_comment = db.get_comment_by_id(comment_id, include_hidden=True)
        
        if new_comment:
            comment_data = {
                'id': new_comment['id'],
                'text': new_comment['mensagem'],
                'date': new_comment['data_comentario']
            }
            return jsonify({'comment': comment_data})
        else:
            return jsonify({'error': 'Erro ao recuperar comentário criado'}), 500
            
    except Exception as e:
        print(f"Erro ao adicionar comentário ao post {post_id}: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

