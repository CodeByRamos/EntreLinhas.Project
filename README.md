# EntreLinhas

EntreLinhas é uma plataforma Flask para desabafos anônimos, com estética escura, misteriosa e acolhedora. O projeto preserva anonimato público, tags emocionais, ECHO, reports, perfil, página de ajuda e moderação.

## Stack

- Python 3
- Flask
- Flask-SQLAlchemy
- Flask-Migrate/Alembic
- PostgreSQL recomendado/obrigatório em produção
- SQLite apenas para desenvolvimento local
- Gunicorn para servidor web
- Storage configurável para uploads: local, Cloudinary ou S3

## Rodar localmente

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -c "import database as db; db.init_db()"
python app.py
```

Acesse `http://127.0.0.1:5000/feed`.

Antes de rodar localmente com o `.env` copiado, ajuste `FLASK_ENV=development` e `ENVIRONMENT=development`. Assim você pode deixar `STORAGE_PROVIDER=local` e usar SQLite. Isso não deve ser usado como banco principal em produção.

## Variáveis principais

- `SECRET_KEY`: obrigatória em produção.
- `DATABASE_URL`: PostgreSQL em produção. URLs `postgres://` são normalizadas e o SQLAlchemy usa o driver `psycopg` automaticamente.
- `STORAGE_PROVIDER`: `local`, `cloudinary` ou `s3`.
- `UPLOAD_FOLDER`: usado apenas no storage local.
- `MAX_CONTENT_LENGTH`: limite geral de upload.
- `PROFILE_PHOTO_MAX_BYTES`: limite de foto de perfil.
- `SESSION_COOKIE_SECURE`: use `true` em HTTPS.
- `ADMIN_EMAIL` e `ADMIN_PASSWORD`: referência operacional para criação/admin inicial.

## PostgreSQL e migrations

Produção deve usar PostgreSQL:

```bash
set DATABASE_URL=postgresql://usuario:senha@host:5432/banco
flask db upgrade
```

A migration inicial está em `migrations/versions/20260511_0001_production_schema.py` e cria as tabelas necessárias para usuários, posts, comentários, reports, ECHO, textos do dia, apoio emocional, notificações e tokens.

O projeto ainda mantém `database.py` para compatibilidade com a base atual. Quando `DATABASE_URL` aponta para PostgreSQL, as conexões usam PostgreSQL e o SQLite local deixa de ser o caminho principal.

Internamente, a configuração converte `postgresql://` para `postgresql+psycopg://` apenas no SQLAlchemy/Alembic. A camada legada continua recebendo o URI PostgreSQL puro, compatível com `psycopg`.

## Storage persistente

Uploads locais podem sumir em plataformas como Render, Railway, Fly.io ou Heroku-like. Em produção, configure um provider persistente.

Cloudinary:

```env
STORAGE_PROVIDER=cloudinary
CLOUDINARY_CLOUD_NAME=
CLOUDINARY_API_KEY=
CLOUDINARY_API_SECRET=
```

S3:

```env
STORAGE_PROVIDER=s3
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_S3_BUCKET=
AWS_REGION=
AWS_PUBLIC_BASE_URL=
```

O storage local fica disponível apenas como fallback de desenvolvimento.

## Criar admin

```bash
python -c "import database as db; db.init_db(); print(db.ensure_admin_user('admin', 'troque-esta-senha', nickname='Admin', email='admin@example.com'))"
```

Depois acesse `/admin/login`.

## Deploy

Start command:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```

Configuração mínima:

- `ENVIRONMENT=production`
- `FLASK_ENV=production`
- `SECRET_KEY` configurada
- `DATABASE_URL` com PostgreSQL
- `SESSION_COOKIE_SECURE=true`
- `STORAGE_PROVIDER=cloudinary` ou `s3`
- migrations rodadas com `flask db upgrade`

## QA antes de publicar

Use:

- `DEPLOY_CHECKLIST.md`
- `QA_DEVICE_CHECKLIST.md`

Teste cadastro, login, logout, feed, novo desabafo, conteúdo sensível, ECHO, reports, perfil, upload de foto, páginas legais, admin, responsividade e persistência após redeploy.
