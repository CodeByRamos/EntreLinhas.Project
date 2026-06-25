"""Cartas para Desconhecidos: fluxo + hardening da revisão."""
import database as db
import db_features as dbf


def _deliver(letter_id, recipient_id):
    """Força a entrega de uma carta específica a um destinatário (para teste)."""
    conn = db._open_raw_connection()
    conn.execute(
        "INSERT INTO stranger_letter_deliveries (letter_id, recipient_id, action, created_at) "
        "VALUES (?, ?, NULL, ?)",
        (letter_id, recipient_id, "01/01/2026 00:00"),
    )
    conn.commit()
    conn.close()


def test_full_letter_exchange(make_user):
    a, b = make_user(), make_user()
    lid = dbf.create_stranger_letter(a, "Querido desconhecido, isto é um teste de carta.")
    assert lid
    _deliver(lid, b)
    assert dbf.get_delivered_letter(lid, b) is not None
    assert dbf.respond_to_letter(b, lid, "Eu te ouvi, você não está sozinho.") is True
    # o autor original recebe a resposta + uma notificação
    replies = dbf.get_received_replies(a)
    assert len(replies) >= 1
    assert db.count_unread_notifications(a) >= 1


def test_cannot_respond_twice(make_user):
    a, b = make_user(), make_user()
    lid = dbf.create_stranger_letter(a, "Carta para testar resposta única por pessoa.")
    _deliver(lid, b)
    assert dbf.respond_to_letter(b, lid, "primeira resposta válida aqui") is True
    assert dbf.respond_to_letter(b, lid, "segunda resposta deve ser barrada") is False


def test_report_dedup_and_preserves_action(make_user):
    a, b = make_user(), make_user()
    lid = dbf.create_stranger_letter(a, "Carta para testar denúncia e estado da entrega.")
    _deliver(lid, b)
    dbf.set_delivery_action(lid, b, "read")
    assert dbf.report_stranger_letter(lid, b) is True
    assert dbf.report_stranger_letter(lid, b) is False  # dedup
    row = db._open_raw_connection().execute(
        "SELECT action, reported_at FROM stranger_letter_deliveries WHERE letter_id=? AND recipient_id=?",
        (lid, b)).fetchone()
    assert row["action"] == "read"          # NÃO foi sobrescrito por 'reported'
    assert row["reported_at"]


def test_hidden_letter_disappears_from_reading(make_user):
    a, b = make_user(), make_user()
    lid = dbf.create_stranger_letter(a, "Carta que será ocultada por denúncias no teste.")
    _deliver(lid, b)
    assert dbf.get_delivered_letter(lid, b) is not None
    conn = db._open_raw_connection()
    conn.execute("UPDATE stranger_letters SET is_hidden = 1 WHERE id = ?", (lid,))
    conn.commit()
    conn.close()
    assert dbf.get_delivered_letter(lid, b) is None


def test_anti_spam_open_letter_cap(logged_client):
    uid = logged_client._test_user_id
    for i in range(dbf.MAX_OPEN_LETTERS if False else 6):
        logged_client.post("/cartas/desconhecidos/escrever",
                           data={"content": f"Carta numero {i} de teste para o limite de circulacao."})
    from routes.letters import MAX_OPEN_LETTERS
    assert dbf.count_open_letters_by_author(uid) <= MAX_OPEN_LETTERS
