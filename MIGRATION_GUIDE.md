# Guia de Migração — EntreLinhas para produção (Supabase + Render)

Passo a passo, sem assumir conhecimento prévio. Ao final, o site estará no ar com
banco PostgreSQL no **Supabase** e hospedagem no **Render**.

Tempo estimado: 30–45 minutos. Tudo usa planos gratuitos.

---

## Visão geral

| Peça | Onde fica | Para quê |
|------|-----------|----------|
| Banco de dados | **Supabase** (PostgreSQL) | guarda usuários, posts, comentários, tudo |
| Aplicação web | **Render** (roda o Flask) | serve o site |
| Fotos de perfil | **Cloudinary** | o disco do Render é apagado a cada deploy |
| E-mails | **Gmail** (senha de app) | verificação de conta e recuperação de senha |

> ⚠️ O `app.py` **recusa subir em produção** sem PostgreSQL, sem storage persistente
> e sem SMTP. É proposital: evita perder dados e e-mails em silêncio.

---

## 1. Criar o projeto no Supabase (banco de dados)

1. Acesse **https://supabase.com** → **Start your project** → entre com o GitHub.
2. **New project**:
   - **Name**: `entrelinhas`
   - **Database Password**: clique em **Generate a password** e **guarde essa senha**
     (você vai precisar dela no passo 2).
   - **Region**: escolha a mais perto do Brasil (ex.: `South America (São Paulo)`).
3. Clique em **Create new project** e espere ~2 minutos até ficar pronto.

## 2. Copiar a connection string (DATABASE_URL)

1. No projeto do Supabase, clique em **Connect** (botão no topo).
2. Na aba **Connection string**, escolha **Session pooler** (é compatível com IPv4,
   que o Render usa).
3. Copie a URL. Ela tem este formato:
   ```
   postgresql://postgres.abcdefgh:[YOUR-PASSWORD]@aws-0-sa-east-1.pooler.supabase.com:5432/postgres
   ```
4. Troque `[YOUR-PASSWORD]` pela senha que você guardou no passo 1.
5. Guarde essa URL final — é o valor de **`DATABASE_URL`**.

> Por que "Session pooler" e não "Direct connection"? A conexão direta do Supabase
> é só IPv6, e o Render precisa de IPv4. O pooler resolve isso. O código já desliga
> os *prepared statements* automáticos, então funciona sem ajuste.

## 3. Criar as tabelas no banco (migrations)

Você pode rodar as migrations do seu próprio computador, uma única vez.

No terminal, dentro da pasta do projeto:

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows.  No Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt

# cole aqui a URL do passo 2 (Windows PowerShell):
$env:DATABASE_URL = "postgresql://postgres.abcdefgh:SUA_SENHA@aws-0-sa-east-1.pooler.supabase.com:5432/postgres"
python -m flask db upgrade
```

No Mac/Linux, troque a linha do `$env:` por:
```bash
export DATABASE_URL="postgresql://postgres.abcdefgh:SUA_SENHA@aws-0-sa-east-1.pooler.supabase.com:5432/postgres"
python -m flask db upgrade
```

Se aparecer algo como `Running upgrade -> ...`, as tabelas foram criadas. ✅
(Você pode conferir no Supabase em **Table Editor**.)

> Não precisa rodar isso de novo: no Render, o próprio start roda `flask db upgrade`
> automaticamente a cada deploy (é idempotente — não recria nem apaga nada).

## 4. Cloudinary (fotos de perfil)

1. Crie conta grátis em **https://cloudinary.com**.
2. No **Dashboard**, copie três valores: **Cloud name**, **API Key**, **API Secret**.

## 5. Senha de app do Gmail (e-mails)

1. Na sua Conta Google, ative a **Verificação em duas etapas** (obrigatório).
2. Vá em **Conta Google → Segurança → Senhas de app**.
3. Crie uma para "EntreLinhas" e copie os **16 dígitos** (sem espaços).

## 6. Subir o código para o GitHub

O Render faz deploy a partir do GitHub.

```bash
git add -A
git commit -m "Preparar produção: Supabase + Render"
git push origin main
```

## 7. Criar o serviço no Render

1. Acesse **https://render.com** → entre com o GitHub.
2. **New +** → **Blueprint** → conecte o repositório do EntreLinhas.
3. O Render lê o `render.yaml` e cria **1 web service** (o banco NÃO é criado aqui —
   ele já está no Supabase). Confirme.
4. `SECRET_KEY` é gerada automaticamente pelo Render.

## 8. Preencher as variáveis no Render

No web service → aba **Environment**, preencha os campos marcados como *sync:false*:

| Variável | Valor |
|----------|-------|
| `DATABASE_URL` | a URL do Supabase do passo 2 |
| `APP_BASE_URL` | a URL do serviço, ex.: `https://entrelinhas.onrender.com` |
| `CLOUDINARY_CLOUD_NAME` / `CLOUDINARY_API_KEY` / `CLOUDINARY_API_SECRET` | do passo 4 |
| `MAIL_USERNAME` | seu_email@gmail.com |
| `MAIL_PASSWORD` | os 16 dígitos do passo 5 |
| `MAIL_DEFAULT_SENDER` | `EntreLinhas <seu_email@gmail.com>` |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | credenciais do primeiro admin |

Clique em **Save changes** → o Render faz o deploy.

## 9. Testar a aplicação (smoke test)

Com o site no ar, confirme cada fluxo (é o que valida o banco de verdade):

- [ ] Abrir `/feed` (carrega, sem erro 500)
- [ ] Criar conta em `/registro` → chega o e-mail de verificação
- [ ] Clicar no link do e-mail e verificar a conta
- [ ] Publicar um desabafo
- [ ] Reagir e comentar
- [ ] `/esqueci-senha` → chega o e-mail e a senha é redefinida
- [ ] Subir foto de perfil em `/perfil/editar` (vai para o Cloudinary)
- [ ] Entrar em `/admin/login` com o ADMIN_EMAIL/ADMIN_PASSWORD
- [ ] Fazer um redeploy no Render e confirmar que os dados continuam lá (persistência)

---

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---------|----------------|---------|
| Deploy falha logo no boot | falta `DATABASE_URL`, `STORAGE_PROVIDER` ou SMTP | preencha as variáveis do passo 8 |
| Erro de conexão com o banco | usou a "Direct connection" (IPv6) | troque para a **Session pooler** (passo 2) |
| `flask db upgrade` falha localmente | `DATABASE_URL` não exportada no terminal | repita o passo 3 na mesma janela do terminal |
| Primeiro acesso demora ~30s | plano grátis do Render "dorme" | normal; o segundo acesso é rápido |
| E-mails não chegam | senha de app errada ou 2FA desligado | refaça o passo 5 |

## Notas

- **SQLite** só é usado em desenvolvimento local (quando `DATABASE_URL` está vazia) e
  nos testes automatizados. Em produção o banco é sempre o PostgreSQL do Supabase.
- `runtime.txt` fixa **Python 3.12** (o Render respeita).
- Para rodar localmente sem Supabase, basta deixar `DATABASE_URL` vazio: o app usa o
  SQLite local automaticamente.
