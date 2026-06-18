# Deploy do EntreLinhas na Render

Guia passo a passo. O código já está pronto: `render.yaml` (Blueprint), `Procfile`
(roda migrations + gunicorn), Postgres via `DATABASE_URL`, e a camada de banco já
tem o caminho PostgreSQL testado estaticamente.

## 0. Pré-requisitos (contas que só você pode criar)

| Serviço | Para quê | Plano |
|--------|----------|-------|
| **Render** | hospedar o site + banco Postgres | grátis |
| **Cloudinary** | guardar as fotos de perfil (o disco da Render é efêmero) | grátis |
| **Senha de app do Gmail** | enviar e-mails de verificação/recuperação | grátis (exige 2FA na conta Google) |

> O `app.py` **bloqueia** a subida em produção se faltar Postgres, storage persistente
> ou SMTP. Isso é proposital: evita perder dados e e-mails silenciosamente.

### Como gerar a senha de app do Gmail
1. Ative a verificação em 2 etapas na sua Conta Google.
2. Vá em **Conta Google → Segurança → Senhas de app**.
3. Crie uma para "EntreLinhas" → copie os **16 dígitos** (sem espaços).

### Cloudinary
Crie a conta → no Dashboard copie **Cloud name**, **API Key** e **API Secret**.

## 1. Subir o código para o GitHub
A Render faz deploy a partir do GitHub. Garanta que o branch `main` está atualizado:
```
git add -A
git commit -m "Front-end na identidade v2, filtro sensível e prontidão para deploy"
git push origin main
```

## 2. Criar tudo na Render via Blueprint
1. Painel da Render → **New + → Blueprint**.
2. Conecte o repositório `CodeByRamos/EntreLinhas.Project`.
3. A Render lê o `render.yaml` e propõe **1 web service + 1 banco Postgres**. Confirme.
4. `SECRET_KEY` é gerada automaticamente e `DATABASE_URL` é ligada ao banco sozinha.

## 3. Preencher os segredos (Environment do web service)
Os marcados como `sync:false` ficam vazios — preencha:

| Variável | Valor |
|----------|-------|
| `APP_BASE_URL` | a URL do serviço, ex.: `https://entrelinhas.onrender.com` |
| `CLOUDINARY_CLOUD_NAME` / `CLOUDINARY_API_KEY` / `CLOUDINARY_API_SECRET` | do Dashboard do Cloudinary |
| `MAIL_USERNAME` | seu_email@gmail.com |
| `MAIL_PASSWORD` | os 16 dígitos da senha de app |
| `MAIL_DEFAULT_SENDER` | `EntreLinhas <seu_email@gmail.com>` |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | credenciais do primeiro admin |

Salve → a Render redeploya.

## 4. Primeiro boot
O start (`flask db upgrade && gunicorn`) cria as tabelas e sobe o app.
Crie o admin (Render → Shell do serviço):
```
flask create-admin
```

## 5. Smoke test (certificação final da stack)
Com o site no ar, confirme cada fluxo principal — é o que valida o Postgres de verdade:
- [ ] Abrir `/feed` (200, sem erro 500)
- [ ] Criar conta em `/registro` → recebe e-mail de verificação
- [ ] Verificar o e-mail pelo link
- [ ] Publicar um desabafo
- [ ] Reagir e comentar
- [ ] `/esqueci-senha` → recebe e redefine a senha
- [ ] Subir foto de perfil em `/perfil/editar` (vai pro Cloudinary)
- [ ] Entrar em `/admin/login`
- [ ] Postar conteúdo com discurso de ódio ofuscado → deve ser barrado

## Notas
- `runtime.txt` fixa Python 3.11 (a Render respeita).
- Plano grátis da Render **dorme** após inatividade (primeiro acesso demora ~30s).
- O Postgres grátis da Render expira em ~90 dias — para algo duradouro, migre para um pago
  ou um Neon/Supabase grátis depois (basta trocar `DATABASE_URL`).
