from flask import Blueprint, request, jsonify, session, current_app
import database as db
from utils.validation import LIMITS
from utils.api_errors import api_error
from extensions import limiter

reports = Blueprint('reports', __name__)


def _admin_session_valid():
    if not session.get('admin_logged_in') or not session.get('admin_user_id'):
        return False
    admin_user = db.get_user_by_id(session['admin_user_id'])
    return bool(admin_user and admin_user['is_admin'])


@reports.route('/api/report', methods=['POST'])
@limiter.limit('20 per minute; 100 per hour')
def reportar_post():
    # Exige login: denúncia anônima permitia floodar a fila de moderação.
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Entre na sua conta para avisar a moderação.', 'auth_required': True}), 401
    try:
        data = request.get_json(silent=True) or {}
        try:
            post_id = int(data.get('post_id'))
        except (TypeError, ValueError):
            return jsonify({'success': False, 'message': 'Não conseguimos identificar esse desabafo.'}), 400
        reason = (data.get('reason') or 'outro').strip()
        details = (data.get('details') or '').strip()

        if details and len(details) > LIMITS["report_details_max"]:
            return jsonify({'success': False, 'message': 'Conte um pouco menos nos detalhes para conseguirmos receber seu aviso.'}), 400

        post = db.get_post(post_id)
        if not post:
            return jsonify({'success': False, 'message': 'Esse desabafo não está mais disponível.'}), 404

        # Deduplicação por usuário logado (create_report já ignora report repetido).
        success, message = db.create_report(
            post_id,
            user_id=session['user_id'],
            reason=reason,
            details=details,
        )

        if not success:
            return jsonify({'success': False, 'message': message}), 400

        return jsonify({
            'success': True,
            'message': message,
            'report_count': db.get_report_count(post_id),
        })
    except Exception as exc:
        current_app.logger.exception("REPORT_POST_ERROR")
        return jsonify(api_error("Não conseguimos enviar seu aviso agora.", exc)), 500


@reports.route('/api/report/<int:post_id>', methods=['DELETE'])
@limiter.limit('30 per minute')
def desfazer_report(post_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Entre na sua conta para desfazer um aviso.', 'auth_required': True}), 401
    try:
        success, message = db.remove_report(post_id, user_id=session['user_id'])
        if success:
            return jsonify({'success': True, 'message': message, 'report_count': db.get_report_count(post_id)})
        return jsonify({'success': False, 'message': message}), 400
    except Exception as exc:
        current_app.logger.exception("REPORT_UNDO_ERROR post_id=%s", post_id)
        return jsonify(api_error("Não conseguimos desfazer esse aviso agora.", exc)), 500


@reports.route('/api/report-count/<int:post_id>', methods=['GET'])
def obter_contagem_reports(post_id):
    try:
        return jsonify({'success': True, 'count': db.get_report_count(post_id)})
    except Exception:
        return jsonify({'success': False, 'message': 'Não conseguimos carregar os avisos agora.'}), 500


@reports.route('/api/admin/reports', methods=['GET'])
def listar_reports():
    try:
        if not _admin_session_valid():
            return jsonify({'success': False, 'message': 'Acesso restrito à moderação.'}), 403
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page
        status = request.args.get('status') or None
        reports_list = db.get_all_reports(limit=per_page, offset=offset, status=status)
        return jsonify({'success': True, 'reports': [dict(report) for report in reports_list], 'page': page})
    except Exception:
        return jsonify({'success': False, 'message': 'Não conseguimos carregar os avisos agora.'}), 500


@reports.route('/api/admin/reports/<int:post_id>', methods=['GET'])
def obter_reports_post(post_id):
    try:
        if not _admin_session_valid():
            return jsonify({'success': False, 'message': 'Acesso restrito à moderação.'}), 403
        reports_list = db.get_reports_by_post(post_id)
        return jsonify({'success': True, 'reports': [dict(report) for report in reports_list]})
    except Exception:
        return jsonify({'success': False, 'message': 'Não conseguimos carregar os avisos agora.'}), 500


@reports.route('/api/report_comment/<int:comment_id>', methods=['POST'])
@limiter.limit('20 per minute; 100 per hour')
def reportar_comentario(comment_id):
    # Exige login: sem isso, qualquer visitante anônimo floodava avisos de resposta.
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Entre na sua conta para avisar a moderação.', 'auth_required': True}), 401
    try:
        data = request.get_json(silent=True) or {}
        reason = (data.get('reason') or 'Conteúdo inadequado')
        comment = db.get_comment_by_id(comment_id)
        if not comment:
            return jsonify({'success': False, 'message': 'Comentário não encontrado.'}), 404
        success = db.report_comment(comment_id, reason, user_id=session['user_id'])
        if success:
            return jsonify({'success': True, 'message': 'A moderação recebeu seu aviso.'})
        return jsonify({'success': False, 'message': 'Você já avisou sobre esta resposta.'}), 409
    except Exception as exc:
        current_app.logger.exception("REPORT_COMMENT_ERROR comment_id=%s", comment_id)
        return jsonify(api_error("Não conseguimos enviar seu aviso agora.", exc)), 500
