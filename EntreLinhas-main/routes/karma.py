from flask import Blueprint, request, jsonify, session
import database as db

# Criação do Blueprint para as rotas de karma de comentários
karma = Blueprint('karma', __name__)

@karma.route('/api/comment-karma', methods=['POST'])
def votar_karma_comentario():
    """Rota para votar no karma de um comentário."""
    try:
        data = request.get_json()
        comment_id = data.get('comment_id')
        karma_type = data.get('karma_type')  # 'up' ou 'down'
        
        if not comment_id or not karma_type:
            return jsonify({'success': False, 'message': 'Dados incompletos.'}), 400
        
        if karma_type not in ['up', 'down']:
            return jsonify({'success': False, 'message': 'Tipo de karma inválido.'}), 400
        
        # Verificar se o usuário está logado
        token = session.get('profile_token')
        if not token:
            return jsonify({'success': False, 'message': 'É necessário estar logado para votar.'}), 401
        
        # Obter o perfil do usuário
        profile = db.get_profile_by_token(token)
        if not profile:
            return jsonify({'success': False, 'message': 'Perfil não encontrado.'}), 404
        
        profile_id = profile['id']
        
        # Verificar se o comentário existe
        comment = db.get_comment_by_id(comment_id)
        if not comment:
            return jsonify({'success': False, 'message': 'Comentário não encontrado.'}), 404
        
        # Verificar se o usuário já votou neste comentário
        existing_karma = db.get_user_comment_karma(comment_id, profile_id)
        
        if existing_karma == karma_type:
            # Se já votou no mesmo tipo, remover o voto
            success, message = db.remove_comment_karma(comment_id, profile_id)
            action = 'removed'
        else:
            # Adicionar ou atualizar o voto
            success, message = db.add_comment_karma(comment_id, profile_id, karma_type)
            action = 'added'
        
        if success:
            # Obter o score atualizado
            score, up_votes, down_votes = db.get_comment_karma_score(comment_id)
            
            return jsonify({
                'success': True,
                'message': message,
                'action': action,
                'score': score,
                'up_votes': up_votes,
                'down_votes': down_votes,
                'user_karma': None if action == 'removed' else karma_type
            })
        else:
            return jsonify({'success': False, 'message': message}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

@karma.route('/api/comment-karma/<int:comment_id>', methods=['GET'])
def obter_karma_comentario(comment_id):
    """Rota para obter o karma de um comentário."""
    try:
        score, up_votes, down_votes = db.get_comment_karma_score(comment_id)
        
        # Verificar se o usuário está logado e qual seu voto
        user_karma = None
        token = session.get('profile_token')
        if token:
            profile = db.get_profile_by_token(token)
            if profile:
                user_karma = db.get_user_comment_karma(comment_id, profile['id'])
        
        return jsonify({
            'success': True,
            'score': score,
            'up_votes': up_votes,
            'down_votes': down_votes,
            'user_karma': user_karma
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

@karma.route('/api/high-karma-comments', methods=['GET'])
def obter_comentarios_alto_karma():
    """Rota para obter comentários com karma alto."""
    try:
        min_karma = request.args.get('min_karma', 10, type=int)
        limit = request.args.get('limit', 50, type=int)
        
        comments = db.get_high_karma_comments(min_karma, limit)
        
        return jsonify({
            'success': True,
            'comments': [dict(comment) for comment in comments]
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

