"""Robustez: conexão de escopo de requisição não vaza."""
import database as db


def test_same_connection_within_request(app):
    with app.test_request_context("/"):
        c1 = db.get_db_connection()
        c2 = db.get_db_connection()
        assert c1 is c2
        assert type(c1).__name__ == "_RequestConn"
        assert c1.close() is None  # no-op
        # ainda usável após close()
        assert db.get_db_connection().execute("SELECT 1").fetchone() is not None


def test_outside_request_is_raw(app):
    # Sem contexto de app, devolve conexão avulsa (não o handle de request)
    conn = db.get_db_connection()
    assert type(conn).__name__ != "_RequestConn"
    conn.close()


def test_no_connection_leak_across_requests(app, monkeypatch):
    opens = {"n": 0}
    releases = {"n": 0}
    orig_open = db._open_raw_connection
    orig_close = db.close_request_connection

    def counting_open():
        opens["n"] += 1
        return orig_open()

    def counting_close(exc=None):
        from flask import g
        had = getattr(g, "_db_handle", None) is not None
        orig_close(exc)
        if had:
            releases["n"] += 1

    monkeypatch.setattr(db, "_open_raw_connection", counting_open)
    monkeypatch.setattr(db, "close_request_connection", counting_close)

    c = app.test_client()
    for url in ["/feed", "/sobre", "/pulso", "/rota-inexistente"]:
        c.get(url)
    assert opens["n"] > 0
    assert opens["n"] == releases["n"]   # tudo que abriu, fechou
