Esta pasta contém a configuração Alembic/Flask-Migrate para produção.

Uso recomendado:

```bash
set FLASK_APP=app.py
set DATABASE_URL=postgresql://usuario:senha@host:5432/banco
flask db upgrade
```

Notas:

- Produção deve usar PostgreSQL.
- SQLite continua existindo apenas para desenvolvimento local e compatibilidade.
- A migration `20260511_0001_production_schema.py` cria o schema principal.
- URLs iniciadas com `postgres://` são normalizadas, e o Alembic usa `postgresql+psycopg://` automaticamente.
