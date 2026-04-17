from flask import Blueprint, render_template, redirect, url_for, flash, session, request, jsonify
import database as db

notifications = Blueprint("notifications", __name__)


def _require_login():
    if "user_id" not in session:
        flash("Faça login para acessar notificações.", "error")
        return redirect(url_for("auth.login", next=url_for("notifications.list_notifications")))
    return None


@notifications.route("/notificacoes", methods=["GET"])
def list_notifications():
    auth = _require_login()
    if auth:
        return auth
    rows = db.get_notifications_by_user(session["user_id"], limit=50)
    return render_template("notifications/list.html", notifications=rows)


@notifications.route("/notificacoes/<int:notification_id>/lida", methods=["POST"])
def mark_as_read(notification_id):
    auth = _require_login()
    if auth:
        return auth
    success = db.mark_notification_as_read(notification_id, session["user_id"])
    if request.is_json:
        return jsonify({"success": success}), (200 if success else 404)
    if not success:
        flash("Notificação não encontrada para o seu usuário.", "error")
    return redirect(url_for("notifications.list_notifications"))