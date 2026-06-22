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


def set_psychologist_status(psych_id, status):
    if status not in ("approved", "rejected", "pending"):
        return False
    conn = get_db_connection()
    is_verified = 1 if status == "approved" else 0
    conn.execute(
        "UPDATE psychologists SET status = ?, is_verified = ? WHERE id = ?",
        (status, is_verified, psych_id),
    )
    conn.commit()
    conn.close()
    return True


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
