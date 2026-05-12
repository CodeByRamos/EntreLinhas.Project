# EntreLinhas

EntreLinhas é uma plataforma Flask para desabafos anônimos, com estética escura, misteriosa e acolhedora. O projeto preserva anonimato público, tags emocionais, ECHO, reports, perfil, página de ajuda, moderação e fluxos reais de autenticação por e-mail.

## Stack

- Python 3
- Flask
- Flask-SQLAlchemy
- Flask-Migrate/Alembic
- PostgreSQL obrigatório em produção
- SQLite apenas como fallback local de desenvolvimento
- Gunicorn para servidor web
- SMTP configurável para verificação de e-mail e recuperação de senha
- Storage configurável para uploads: local, Cloudinary ou S3

## Rodar localmente

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -m flask db upgrade
python app.py
```

Acesse `http://127.0.0.1:5000/feed`.

No ambiente local, mantenha `FLASK_ENV=development`, `ENVIRONMENT=development` e `STORAGE_PROVIDER=local`. Se `DATABASE_URL` ficar vazio, o app usa SQLite apenas para desenvolvimento. Isso não deve ser usado como banco principal em produção.

## Variáveis principais

- `SECRET_KEY`: obrigatória em produção.
- `APP_BASE_URL`: URL pública usada nos links de e-mail, por exemplo `https://entrelinhas.com`.
- `DATABASE_URL`: PostgreSQL em produção. URLs `postgres://` são normalizadas para `postgresql://`.
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`: SMTP real para produção.
- `MAIL_ALLOW_CONSOLE_FALLBACK`: use `true` só em desenvolvimento para imprimir links no terminal.
- `STORAGE_PROVIDER`: `local`, `cloudinary` ou `s3`.
- `UPLOAD_FOLDER`: usado apenas no storage local.
- `MAX_CONTENT_LENGTH`: limite geral de upload.
- `PROFILE_PHOTO_MAX_BYTES`: limite de foto de perfil.
- `SESSION_COOKIE_SECURE`: use `true` em HTTPS.
- `ADMIN_EMAIL` e `ADMIN_PASSWORD`: usados para criar ou resetar o admin.

## PostgreSQL e migrations

Produção deve usar PostgreSQL:

```bash
set DATABASE_URL=postgresql://usuario:senha@host:5432/banco
python -m flask db upgrade
```

A migration inicial está em `migrations/versions/20260511_0001_production_schema.py` e cria as tabelas necessárias para usuários, posts, comentários, reports, ECHO, textos do dia, apoio emocional, notificações e tokens.

O projeto ainda mantém `database.py` para compatibilidade com a base atual. Quando `DATABASE_URL` aponta para PostgreSQL, as conexões usam PostgreSQL e o SQLite local deixa de ser o caminho principal. Internamente, a configuração converte `postgresql://` para `postgresql+psycopg://` no SQLAlchemy/Alembic.

## E-mail, verificação e senha

O cadastro cria a conta com e-mail e senha em hash. O app gera um token seguro no banco e envia um link de confirmação para:

```txt
/verificar-email/<token>
```

A recuperação de senha usa o mesmo padrão, com token de expiração curta:

```txt
/esqueci-senha
/redefinir-senha/<token>
```

Em desenvolvimento, se SMTP não estiver configurado e `MAIL_ALLOW_CONSOLE_FALLBACK=true`, o link é impresso no terminal. Em produção, configure SMTP real e mantenha `MAIL_ALLOW_CONSOLE_FALLBACK=false`.

Exemplo de SMTP:

```env
APP_BASE_URL=https://seu-dominio.com
MAIL_SERVER=smtp.seu-provedor.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=usuario
MAIL_PASSWORD=senha
MAIL_DEFAULT_SENDER=EntreLinhas <nao-responda@seu-dominio.com>
MAIL_ALLOW_CONSOLE_FALLBACK=false
```

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

## Criar ou resetar admin

Defina as variáveis:

```env
ADMIN_EMAIL=admin@entrelinhas.com
ADMIN_PASSWORD=sua_senha_segura
```

`ADMIN_USERNAME` é opcional. Se ele não for definido, o sistema cria um username seguro a partir do e-mail.

Rode:

```bash
python scripts/create_admin.py
```

Ou use o comando Flask:

```bash
python -m flask create-admin
```

O comando cria o admin se ele não existir. Se já existir uma conta com o `ADMIN_EMAIL`, ele atualiza a senha, reativa a conta e garante `role='admin'` e `is_admin=1`. Depois acesse `/admin/login` com o e-mail e a senha definidos.

## Deploy

Start command:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```

Configuração mínima:

- `ENVIRONMENT=production`
- `FLASK_ENV=production`
- `SECRET_KEY` configurada
- `APP_BASE_URL` com o domínio público
- `DATABASE_URL` com PostgreSQL
- `MAIL_SERVER` e `MAIL_DEFAULT_SENDER` configurados
- `MAIL_ALLOW_CONSOLE_FALLBACK=false`
- `SESSION_COOKIE_SECURE=true`
- `STORAGE_PROVIDER=cloudinary` ou `s3`
- migrations rodadas com `python -m flask db upgrade`

## QA antes de publicar

Use:

- `DEPLOY_CHECKLIST.md`
- `QA_DEVICE_CHECKLIST.md`

Teste cadastro, verificação de e-mail, recuperação de senha, login, logout, feed, novo desabafo, conteúdo sensível, ECHO, reports, perfil, upload de foto, páginas legais, admin, responsividade e persistência após redeploy.
