Esta pasta prepara a evolucao para Flask-Migrate/Alembic e PostgreSQL.

Estado atual:
- O app segue usando `database.py` e SQLite local para preservar compatibilidade.
- `models/sqlalchemy_schema.py` documenta o alvo SQLAlchemy.
- `versions/20260511_emotional_features.sql` registra a migracao equivalente para o schema atual.

Proximo passo seguro:
1. Inicializar Flask-Migrate quando a troca de persistencia for feita.
2. Apontar `DATABASE_URL` para PostgreSQL.
3. Converter gradualmente as funcoes de `database.py` para repositorios SQLAlchemy.
