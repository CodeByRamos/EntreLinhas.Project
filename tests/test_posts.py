"""Desabafos: criação, marco de superação, listagens trazem as colunas novas."""
import database as db
from conftest import make_post


def test_create_post_persists(logged_client):
    uid = logged_client._test_user_id
    r = logged_client.post("/enviar", data={
        "conteudo": "Um desabafo de teste com tamanho suficiente para passar.",
        "categoria": "saúde", "emotional_tag": "vazio",
        "visibility_mode": "anonymous", "comment_mode": "open", "action": "publish",
    })
    assert r.status_code == 302
    posts = db.get_posts_by_user(uid, limit=10)
    assert any("desabafo de teste" in p["mensagem"] for p in posts)


def test_listen_only_post_stored(logged_client):
    uid = logged_client._test_user_id
    logged_client.post("/enviar", data={
        "conteudo": "Desabafo somente escuta de teste com tamanho suficiente aqui.",
        "categoria": "saúde", "emotional_tag": "vazio",
        "visibility_mode": "anonymous", "comment_mode": "listen_only", "action": "publish",
    })
    posts = db.get_posts_by_user(uid, limit=10)
    assert any(p["listen_only"] for p in posts)


def test_overcome_mark_and_message(logged_client, make_user):
    uid = logged_client._test_user_id
    pid = make_post(uid)
    r = logged_client.post(f"/posts/{pid}/superei", data={"overcome_message": "Eu consegui."})
    assert r.status_code == 302
    post = db.get_post(pid)
    assert post["overcome_at"]
    assert post["overcome_message"] == "Eu consegui."
    # aparece no histórico de superações com a mensagem
    overcome = db.get_overcome_posts_by_user(uid)
    assert any(p["id"] == pid and p["overcome_message"] == "Eu consegui." for p in overcome)


def test_overcome_only_by_author(logged_client, make_user):
    other_post = make_post(make_user())  # post de OUTRO usuário
    assert db.mark_post_overcome(other_post, logged_client._test_user_id) is False


def test_listing_queries_have_new_columns(logged_client):
    uid = logged_client._test_user_id
    pid = make_post(uid)
    db.mark_post_overcome(pid, uid, message="oi")
    for rows in [db.get_posts(limit=50), db.get_posts_by_user(uid, limit=50),
                 db.get_overcome_posts_by_user(uid, limit=50), db.search_posts("teste", limit=50)]:
        for r in rows:
            keys = r.keys()
            assert "overcome_at" in keys and "overcome_message" in keys and "listen_only" in keys


def test_feed_meta_batches_reactions_and_echo(logged_client):
    # Um único endpoint devolve reações + eco de vários posts (mata o N+1 do feed).
    uid = logged_client._test_user_id
    p1, p2 = make_post(uid), make_post(uid)
    r = logged_client.get(f"/api/feed-meta?ids={p1},{p2}")
    assert r.status_code == 200
    meta = r.get_json()["meta"]
    for pid in (p1, p2):
        assert str(pid) in meta
        assert "reactions" in meta[str(pid)]
        assert "echo" in meta[str(pid)] and "count" in meta[str(pid)]["echo"]


def test_feed_meta_handles_bad_and_empty_ids(logged_client):
    assert logged_client.get("/api/feed-meta").get_json()["meta"] == {}
    assert logged_client.get("/api/feed-meta?ids=abc").status_code == 400
