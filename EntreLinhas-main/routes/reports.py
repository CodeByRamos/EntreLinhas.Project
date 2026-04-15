from flask import Blueprint, request, jsonify, session
import database as db

# Criação do Blueprint para as rotas de reports
reports = Blueprint('reports', __name__)

@reports.route('/api/report', methods=['POST'])
def reportar_post():
    """Rota para reportar um post."""
    try:
        data = request.get_json()
        post_id = data.get('post_id')
        
        if not post_id:
            return jsonify({'success': False, 'message': 'ID do post é obrigatório.'}), 400
        
        # Verificar se o post existe
        post = db.get_post(post_id)
        if not post:
            return jsonify({'success': False, 'message': 'Post não encontrado.'}), 404
        
        # Obter o perfil do usuário (se logado)
        profile_id = None
        token = session.get('profile_token')
        if token:
            profile = db.get_profile_by_token(token)
            if profile:
                profile_id = profile['id']
        
        # Criar o report
        success, message = db.create_report(post_id, profile_id)
        
        if success:
            # Obter a contagem atualizada de reports
            report_count = db.get_report_count(post_id)
            return jsonify({
                'success': True, 
                'message': message,
                'report_count': report_count
            })
        else:
            return jsonify({'success': False, 'message': message}), 400
            
    except Exception as e:
        print(f"Erro ao reportar post {post_id}: {e}")
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

@reports.route('/api/report/<int:post_id>', methods=['DELETE'])
def desfazer_report(post_id):
    """Rota para desfazer um report de um post."""
    try:
        # Obter o perfil do usuário (se logado)
        profile_id = None
        token = session.get('profile_token')
        if token:
            profile = db.get_profile_by_token(token)
            if profile:
                profile_id = profile['id']
        
        # Remover o report
        success, message = db.remove_report(post_id, profile_id)
        
        if success:
            # Obter a contagem atualizada de reports
            report_count = db.get_report_count(post_id)
            return jsonify({
                'success': True, 
                'message': message,
                'report_count': report_count
            })
        else:
            return jsonify({'success': False, 'message': message}), 400
            
    except Exception as e:
        print(f"Erro ao desfazer report do post {post_id}: {e}")
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

@reports.route('/api/report-count/<int:post_id>', methods=['GET'])
def obter_contagem_reports(post_id):
    """Rota para obter a contagem de reports de um post."""
    try:
        count = db.get_report_count(post_id)
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

@reports.route('/admin/reports', methods=['GET'])
def listar_reports():
    """Rota para listar todos os reports (admin)."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page
        
        reports_list = db.get_all_reports(limit=per_page, offset=offset)
        
        return jsonify({
            'success': True,
            'reports': [dict(report) for report in reports_list],
            'page': page
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

@reports.route('/admin/reports/<int:post_id>', methods=['GET'])
def obter_reports_post(post_id):
    """Rota para obter todos os reports de um post específico (admin)."""
    try:
        reports_list = db.get_reports_by_post(post_id)
        
        return jsonify({
            'success': True,
            'reports': [dict(report) for report in reports_list]
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500


@reports.route('/api/report_comment/<int:comment_id>', methods=['POST'])
def reportar_comentario(comment_id):
    """Rota para reportar um comentário."""
    try:
        data = request.get_json()
        reason = data.get('reason', 'Conteúdo inadequado')
        
        # Verificar se o comentário existe
        comment = db.get_comment_by_id(comment_id)
        if not comment:
            return jsonify({'success': False, 'message': 'Comentário não encontrado.'}), 404
        
        # Criar o report do comentário
        success = db.report_comment(comment_id, reason)
        
        if success:
            return jsonify({
                'success': True, 
                'message': 'Comentário reportado com sucesso.'
            })
        else:
            return jsonify({'success': False, 'message': 'Erro ao reportar comentário.'}), 500
            
    except Exception as e:
        print(f"Erro ao reportar comentário {comment_id}: {e}")
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

