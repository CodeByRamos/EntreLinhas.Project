"""Acolher uma voz + notificações vivas."""
import database as db
from conftest import make_post


def test_unanswered_excludes_own_listen_and_answered(make_user):
    me, other = make_user(), make_user()
    open_post = make_post(other)
    listen_post = make_post(other, listen_only=True)
    own_post = make_post(me)
    ids = [r["id"] for r in db.get_unanswered_posts(me, limit=100)]
    assert open_post in ids
    assert listen_post not in ids   # somente escuta não entra
    assert own_post not in ids      # post próprio não entra
    # após responder, sai da fila
    db.create_comment(open_post, "uma resposta com cuidado", user_id=me)
    ids2 = [r["id"] for r in db.get_unanswered_posts(me, limit=100)]
    assert open_post not in ids2


def test_acolher_responder_creates_comment_and_notifies(logged_client, make_user):
    author = make_user()
    pid = make_post(author)
    r = logged_client.post(f"/acolher/{pid}/responder",
                           data={"resposta": "eu te ouvi, você não está sozinho nisso"})
    assert r.status_code == 302
    comments = db.get_comments(pid)
    assert len(comments) >= 1
    assert db.count_unread_notifications(author) >= 1   # autor foi notificado


def test_echo_notifies_post_author(client, make_user):
    author = make_user()
    actor = make_user()
    pid = make_post(author)
    with client.session_transaction() as s:
        s["user_id"] = actor
        s["username"] = "actor"
    r = client.post(f"/api/echo/{pid}", json={})
    assert r.status_code == 200
    assert db.count_unread_notifications(author) >= 1


def test_notifications_mark_read_flow(logged_client):
    uid = logged_client._test_user_id
    db.create_notification(uid, "post_reply", "Título", "Mensagem de teste", reference_id=1)
    assert db.count_unread_notifications(uid) >= 1
    nid = db.get_notifications_by_user(uid, limit=1)[0]["id"]
    # abrir marca como lida e redireciona
    r = logged_client.get(f"/notificacoes/{nid}/ir")
    assert r.status_code in (301, 302)
    # marcar todas zera
    db.create_notification(uid, "echo", "Outra", "Mais uma", reference_id=2)
    logged_client.post("/notificacoes/marcar-todas")
    assert db.count_unread_notifications(uid) == 0


def test_community_pulse_aggregates(make_user):
    uid = make_user()
    for tag in ["tristeza", "tristeza", "esperanca"]:
        make_post(uid, emotional_tag=tag)
    pulse = db.get_community_emotional_pulse(sample=500)
    counts = {r["emotional_tag"]: r["total"] for r in pulse}
    assert counts.get("tristeza", 0) >= 2
