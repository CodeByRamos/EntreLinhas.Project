"""Camada de dados das features de comunidade: apoio psicológico e cartas pro futuro.

Mantida separada do database.py (gigante). Reaproveita a conexão e os helpers de
lá. ATENÇÃO Postgres: todo INSERT fornece os valores das colunas NOT NULL (status,
created_at, etc.) explicitamente — defaults do ORM não valem pra SQL cru.
"""

from datetime import datetime
import logging

from database import get_db_connection, USE_POSTGRES, _ensure_column, _as_datetime
from utils.safe_logging import log_exception

logger = logging.getLogger("entrelinhas.features")


# ---------------------------------------------------------------------------
# Garantia de schema nos dois bancos (colunas novas de psychologists).
# A tabela future_letters é criada pelo SQLAlchemy create_all() no app.py.
# ---------------------------------------------------------------------------

_PSYCH_COLUMNS = [
    # (nome, definição Postgres, definição SQLite)
    ("estado", "VARCHAR(2)", "TEXT"),
    ("cidade", "VARCHAR(80)", "TEXT"),
    ("especialidades", "TEXT", "TEXT"),
    ("modalidade", "VARCHAR(20) DEFAULT 'ambos'", "TEXT DEFAULT 'ambos'"),
    ("photo_url", "TEXT", "TEXT"),
    ("status", "VARCHAR(20) DEFAULT 'pending'", "TEXT DEFAULT 'pending'"),
    # Snapshot da última revisão (Wave 2 — fluxo de aprovação com auditoria)
    ("reviewed_by_id", "INTEGER", "INTEGER"),
    ("reviewed_by_username", "VARCHAR(80)", "TEXT"),
    ("reviewed_at", "VARCHAR(20)", "TEXT"),
    ("review_notes", "TEXT", "TEXT"),
]


def ensure_features_schema():
    """Adiciona as colunas novas de psychologists em SQLite e Postgres (idempotente)."""
    conn = get_db_connection()
    try:
        for name, pg_def, sqlite_def in _PSYCH_COLUMNS:
            try:
                if USE_POSTGRES:
                    conn.execute(f"ALTER TABLE psychologists ADD COLUMN IF NOT EXISTS {name} {pg_def}")
                else:
                    _ensure_column(conn, "psychologists", name, sqlite_def)
            except Exception as exc:
                logger.warning("ensure_features_schema psychologists.%s: %s", name, exc)
        # Rede de segurança pra future_letters em SQLite (em prod o create_all cuida).
        if not USE_POSTGRES:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS future_letters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT,
                    content TEXT NOT NULL,
                    open_at TIMESTAMP NOT NULL,
                    opened_at TIMESTAMP,
                    status TEXT NOT NULL DEFAULT 'SEALED',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        conn.commit()
    except Exception as exc:
        logger.warning("ensure_features_schema falhou: %s", exc)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Apoio psicológico
# ---------------------------------------------------------------------------

def create_psychologist(name, contact_email, crp, estado, cidade,
                        especialidades, bio, contact_link, modalidade, photo_url=None):
    """Cadastra um psicólogo voluntário com status 'pending' (aguardando aprovação)."""
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO psychologists
                (name, contact_email, crp, estado, cidade, especialidades, bio,
                 contact_link, modalidade, photo_url, status, is_verified, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, 1, datetime('now'))
            """,
            (name, contact_email, crp, estado, cidade, especialidades, bio,
             contact_link, modalidade, photo_url),
        )
        conn.commit()
        return True
    except Exception as exc:
        conn.rollback()
        log_exception(logger, "db_features.create_psychologist", "psychologists.insert", exc)
        return False
    finally:
        conn.close()


def get_approved_psychologists(especialidade=None, estado=None, modalidade=None):
    """Lista psicólogos aprovados e ativos, com filtros opcionais."""
    conn = get_db_connection()
    filters = ["status = 'approved'", "is_active = 1"]
    params = []
    if estado:
        filters.append("estado = ?")
        params.append(estado)
    if modalidade in ("online", "presencial"):
        filters.append("(modalidade = ? OR modalidade = 'ambos')")
        params.append(modalidade)
    if especialidade:
        filters.append("LOWER(especialidades) LIKE ?")
        params.append(f"%{especialidade.lower()}%")
    where = " AND ".join(filters)
    rows = conn.execute(
        f"SELECT * FROM psychologists WHERE {where} ORDER BY name ASC",
        tuple(params),
    ).fetchall()
    conn.close()
    return rows


def get_psychologists_by_status(status):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM psychologists WHERE status = ? ORDER BY created_at DESC",
        (status,),
    ).fetchall()
    conn.close()
    return rows


def get_all_psychologists():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM psychologists ORDER BY created_at DESC").fetchall()
    conn.close()
    return rows


PSYCH_STATUSES = ("pending", "approved", "rejected", "changes_requested")


def set_psychologist_status(psych_id, status, reviewer_id=None, reviewer_username=None, notes=None):
    """Muda o status de um cadastro e registra a decisão na trilha de auditoria.

    Só 'approved' fica público (is_verified=1). Toda ação grava quem decidiu,
    quando e a observação, em psychologist_reviews.
    """
    if status not in PSYCH_STATUSES:
        return False
    conn = get_db_connection()
    is_verified = 1 if status == "approved" else 0
    reviewed_at = datetime.now().strftime("%d/%m/%Y %H:%M")
    notes = (notes or "").strip() or None
    try:
        conn.execute(
            "UPDATE psychologists SET status = ?, is_verified = ?, reviewed_by_id = ?, "
            "reviewed_by_username = ?, reviewed_at = ?, review_notes = ? WHERE id = ?",
            (status, is_verified, reviewer_id, reviewer_username, reviewed_at, notes, psych_id),
        )
        conn.execute(
            "INSERT INTO psychologist_reviews "
            "(psychologist_id, action, status_to, notes, reviewer_id, reviewer_username, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (psych_id, status, status, notes, reviewer_id, reviewer_username, reviewed_at),
        )
        conn.commit()
        return True
    except Exception as exc:
        conn.rollback()
        log_exception(logger, "db_features.set_psychologist_status", "psychologists.update", exc)
        return False
    finally:
        conn.close()


def get_psychologist(psych_id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM psychologists WHERE id = ?", (psych_id,)).fetchone()
    conn.close()
    return row


def get_psychologist_reviews(psych_id):
    """Histórico de decisões (mais recente primeiro)."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM psychologist_reviews WHERE psychologist_id = ? ORDER BY id DESC",
        (psych_id,),
    ).fetchall()
    conn.close()
    return rows


def get_psychologist_status_counts():
    """Contagem por status para os badges do painel."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT status, COUNT(*) AS total FROM psychologists GROUP BY status"
    ).fetchall()
    conn.close()
    return {row["status"]: row["total"] for row in rows}


def get_approved_psych_states():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT DISTINCT estado FROM psychologists "
        "WHERE status = 'approved' AND estado IS NOT NULL AND estado <> '' ORDER BY estado"
    ).fetchall()
    conn.close()
    return [row["estado"] for row in rows]


# ---------------------------------------------------------------------------
# Cartas para o futuro
# ---------------------------------------------------------------------------

def create_future_letter(user_id, title, content, open_at):
    """Cria uma carta lacrada. `open_at` é datetime ou string 'YYYY-MM-DD HH:MM:SS'."""
    conn = get_db_connection()
    try:
        open_at_str = open_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(open_at, "strftime") else open_at
        conn.execute(
            """
            INSERT INTO future_letters (user_id, title, content, open_at, status, created_at)
            VALUES (?, ?, ?, ?, 'SEALED', datetime('now'))
            """,
            (user_id, title, content, open_at_str),
        )
        conn.commit()
        return True
    except Exception as exc:
        conn.rollback()
        log_exception(logger, "db_features.create_future_letter", "future_letters.insert", exc)
        return False
    finally:
        conn.close()


def _decorate_letter(row, now):
    letter = dict(row)
    open_at = _as_datetime(row["open_at"]) if row["open_at"] else None
    opened = bool(row["opened_at"]) if "opened_at" in letter else False
    if opened:
        letter["current_status"] = "OPENED"
    elif open_at and now >= open_at:
        letter["current_status"] = "AVAILABLE"
    else:
        letter["current_status"] = "SEALED"
    if open_at and open_at > now:
        delta = open_at - now
        letter["days_remaining"] = delta.days
        letter["open_at_label"] = open_at.strftime("%d/%m/%Y")
    else:
        letter["days_remaining"] = 0
        letter["open_at_label"] = open_at.strftime("%d/%m/%Y") if open_at else "-"
    return letter


def get_user_letters(user_id):
    """Cartas do usuário, com current_status (SEALED/AVAILABLE/OPENED) e contagem."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, user_id, title, content, open_at, opened_at, status, created_at "
        "FROM future_letters WHERE user_id = ? ORDER BY open_at ASC",
        (user_id,),
    ).fetchall()
    conn.close()
    now = datetime.utcnow()
    return [_decorate_letter(row, now) for row in rows]


def get_letter(letter_id, user_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM future_letters WHERE id = ? AND user_id = ?",
        (letter_id, user_id),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return _decorate_letter(row, datetime.utcnow())


def open_future_letter(letter_id, user_id):
    """Abre uma carta SE a data de abertura já chegou. Marca opened_at."""
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT open_at, opened_at FROM future_letters WHERE id = ? AND user_id = ?",
            (letter_id, user_id),
        ).fetchone()
        if not row:
            return False, "Carta não encontrada."
        open_at = _as_datetime(row["open_at"]) if row["open_at"] else None
        if open_at and datetime.utcnow() < open_at:
            return False, "Essa carta ainda está lacrada."
        if not row["opened_at"]:
            conn.execute(
                "UPDATE future_letters SET status = 'OPENED', opened_at = datetime('now') "
                "WHERE id = ? AND user_id = ?",
                (letter_id, user_id),
            )
            conn.commit()
        return True, "Carta aberta."
    except Exception as exc:
        conn.rollback()
        log_exception(logger, "db_features.open_future_letter", "future_letters.update", exc)
        return False, "Não conseguimos abrir a carta agora."
    finally:
        conn.close()


def count_available_letters(user_id):
    """Cartas que acabaram de ficar disponíveis (passou a data, ainda não abertas)."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT open_at, opened_at FROM future_letters WHERE user_id = ? AND opened_at IS NULL",
        (user_id,),
    ).fetchall()
    conn.close()
    now = datetime.utcnow()
    total = 0
    for row in rows:
        open_at = _as_datetime(row["open_at"]) if row["open_at"] else None
        if open_at and now >= open_at:
            total += 1
    return total


# ---------------------------------------------------------------------------
# Cartas para Desconhecidos — troca anônima de cartas entre usuários.
# stranger_letters.parent_id NULL = carta original; != NULL = resposta.
# Identidade do autor NUNCA é exposta na UI (só usada para roteamento/anti-spam).
# ---------------------------------------------------------------------------

def create_stranger_letter(author_id, content, parent_id=None):
    conn = get_db_connection()
    created_at = datetime.now().strftime("%d/%m/%Y %H:%M")
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO stranger_letters (author_id, content, parent_id, is_hidden, report_count, created_at) "
            "VALUES (?, ?, ?, 0, 0, ?)",
            (author_id, content, parent_id, created_at),
        )
        lid = cur.lastrowid
        conn.commit()
        return lid
    except Exception as exc:
        conn.rollback()
        log_exception(logger, "db_features.create_stranger_letter", "stranger_letters.insert", exc)
        return None
    finally:
        conn.close()


def count_open_letters_by_author(author_id):
    """Cartas originais ativas do autor (anti-spam: limita fila por pessoa)."""
    conn = get_db_connection()
    n = conn.execute(
        "SELECT COUNT(*) FROM stranger_letters WHERE author_id = ? AND parent_id IS NULL AND is_hidden = 0",
        (author_id,),
    ).fetchone()[0]
    conn.close()
    return n


def deliver_random_letter(user_id):
    """Entrega uma carta original aleatória que o usuário ainda não recebeu nem
    escreveu, registrando a entrega. Retorna a carta (dict) ou None."""
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT * FROM stranger_letters l
            WHERE l.parent_id IS NULL AND l.is_hidden = 0 AND l.author_id <> ?
              AND NOT EXISTS (
                SELECT 1 FROM stranger_letter_deliveries d
                WHERE d.letter_id = l.id AND d.recipient_id = ?
              )
            ORDER BY RANDOM()
            LIMIT 1
            """,
            (user_id, user_id),
        ).fetchone()
        if not row:
            return None
        created_at = datetime.now().strftime("%d/%m/%Y %H:%M")
        conn.execute(
            "INSERT INTO stranger_letter_deliveries (letter_id, recipient_id, action, created_at) "
            "VALUES (?, ?, NULL, ?)",
            (row["id"], user_id, created_at),
        )
        conn.commit()
        return dict(row)
    except Exception as exc:
        conn.rollback()
        log_exception(logger, "db_features.deliver_random_letter", "deliveries.insert", exc)
        return None
    finally:
        conn.close()


def get_delivered_letter(letter_id, recipient_id):
    """Carta entregue a este usuário (valida a entrega). None se não for dele."""
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT l.*, d.action AS delivery_action
        FROM stranger_letters l
        JOIN stranger_letter_deliveries d ON d.letter_id = l.id
        WHERE l.id = ? AND d.recipient_id = ?
        """,
        (letter_id, recipient_id),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def set_delivery_action(letter_id, recipient_id, action):
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE stranger_letter_deliveries SET action = ? WHERE letter_id = ? AND recipient_id = ?",
            (action, letter_id, recipient_id),
        )
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()


def respond_to_letter(responder_id, parent_letter_id, content):
    """Cria a resposta e a entrega ao autor da carta original."""
    conn = get_db_connection()
    created_at = datetime.now().strftime("%d/%m/%Y %H:%M")
    try:
        original = conn.execute(
            "SELECT id, author_id FROM stranger_letters WHERE id = ? AND is_hidden = 0",
            (parent_letter_id,),
        ).fetchone()
        if not original:
            return False
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO stranger_letters (author_id, content, parent_id, is_hidden, report_count, created_at) "
            "VALUES (?, ?, ?, 0, 0, ?)",
            (responder_id, content, parent_letter_id, created_at),
        )
        reply_id = cur.lastrowid
        conn.execute(
            "INSERT INTO stranger_letter_deliveries (letter_id, recipient_id, action, created_at) "
            "VALUES (?, ?, NULL, ?)",
            (reply_id, original["author_id"], created_at),
        )
        conn.execute(
            "UPDATE stranger_letter_deliveries SET action = 'responded' WHERE letter_id = ? AND recipient_id = ?",
            (parent_letter_id, responder_id),
        )
        conn.commit()
        return True
    except Exception as exc:
        conn.rollback()
        log_exception(logger, "db_features.respond_to_letter", "stranger_letters.reply", exc)
        return False
    finally:
        conn.close()


def get_received_replies(user_id):
    """Respostas entregues a mim (respostas às minhas cartas), mais recentes primeiro."""
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT l.*, d.action AS delivery_action, orig.content AS original_content
        FROM stranger_letter_deliveries d
        JOIN stranger_letters l ON l.id = d.letter_id
        LEFT JOIN stranger_letters orig ON orig.id = l.parent_id
        WHERE d.recipient_id = ? AND l.parent_id IS NOT NULL AND l.is_hidden = 0
        ORDER BY l.id DESC
        """,
        (user_id,),
    ).fetchall()
    conn.close()
    return rows


def count_unread_replies(user_id):
    conn = get_db_connection()
    n = conn.execute(
        """
        SELECT COUNT(*) FROM stranger_letter_deliveries d
        JOIN stranger_letters l ON l.id = d.letter_id
        WHERE d.recipient_id = ? AND l.parent_id IS NOT NULL AND d.action IS NULL AND l.is_hidden = 0
        """,
        (user_id,),
    ).fetchone()[0]
    conn.close()
    return n


def get_my_stranger_letters(user_id):
    """Cartas originais que escrevi, com contagem de respostas."""
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT l.*,
          (SELECT COUNT(*) FROM stranger_letters r WHERE r.parent_id = l.id AND r.is_hidden = 0) AS reply_count
        FROM stranger_letters l
        WHERE l.author_id = ? AND l.parent_id IS NULL
        ORDER BY l.id DESC
        """,
        (user_id,),
    ).fetchall()
    conn.close()
    return rows


def report_stranger_letter(letter_id, user_id, threshold=3):
    """Denúncia: incrementa contagem, deduplica por entrega e oculta no limite."""
    conn = get_db_connection()
    try:
        existing = conn.execute(
            "SELECT action FROM stranger_letter_deliveries WHERE letter_id = ? AND recipient_id = ?",
            (letter_id, user_id),
        ).fetchone()
        if existing and existing["action"] == 'reported':
            return False
        conn.execute("UPDATE stranger_letters SET report_count = report_count + 1 WHERE id = ?", (letter_id,))
        conn.execute(
            "UPDATE stranger_letters SET is_hidden = 1 WHERE id = ? AND report_count >= ?",
            (letter_id, threshold),
        )
        if existing:
            conn.execute(
                "UPDATE stranger_letter_deliveries SET action = 'reported' WHERE letter_id = ? AND recipient_id = ?",
                (letter_id, user_id),
            )
        conn.commit()
        return True
    except Exception as exc:
        conn.rollback()
        log_exception(logger, "db_features.report_stranger_letter", "stranger_letters.report", exc)
        return False
    finally:
        conn.close()
