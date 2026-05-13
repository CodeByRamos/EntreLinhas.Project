# Checklist de Deploy — EntreLinhas

## Antes do deploy
- [ ] Debug desligado
- [ ] `SECRET_KEY` configurada
- [ ] `APP_BASE_URL` aponta para o domínio público
- [ ] `SESSION_COOKIE_SECURE=true` em HTTPS
- [ ] Admin criado/resetado com `python scripts/create_admin.py` ou `python -m flask create-admin`
- [ ] Start command usa `python -m flask db upgrade && gunicorn app:app --bind 0.0.0.0:$PORT`
- [ ] Start command não usa `drop`, `reset`, `create_all` destrutivo ou recriação de banco
- [ ] Static files carregando
- [ ] Logo SVG carregando corretamente
- [ ] Privacidade e Termos publicados
- [ ] Página 404 testada
- [ ] Página 500 revisada
- [ ] QA em dispositivo físico executado

## Banco de dados
- [ ] App usa PostgreSQL em produção
- [ ] `DATABASE_URL` está configurado
- [ ] URL `postgres://` normalizada ou aceita como `postgresql://`
- [ ] `python -m flask db upgrade` executado
- [ ] Migrations rodam sem erro
- [ ] Dados persistem após restart/redeploy
- [ ] SQLite não é usado em produção

## Storage
- [ ] `STORAGE_PROVIDER` configurado como `cloudinary` ou `s3`
- [ ] Uploads testados no storage persistente
- [ ] Foto de perfil aparece após upload
- [ ] Upload persiste após redeploy
- [ ] Arquivos locais são usados apenas em desenvolvimento

## Cadastro e autenticação
- [ ] Cadastro funciona
- [ ] Email duplicado é bloqueado
- [ ] Senha é salva com hash
- [ ] Login funciona
- [ ] Logout funciona
- [ ] Usuário não verificado recebe aviso adequado
- [ ] Reenvio de verificação funciona

## Verificação de email
- [ ] SMTP real configurado em produção
- [ ] `MAIL_ALLOW_CONSOLE_FALLBACK=false` em produção
- [ ] Email de verificação é enviado
- [ ] Link válido verifica a conta
- [ ] Token expirado mostra erro amigável
- [ ] Token inválido não verifica conta

## Recuperação de senha
- [ ] Pedido de reset funciona
- [ ] Mensagem não revela se email existe
- [ ] Email de reset é enviado
- [ ] Link válido permite criar nova senha
- [ ] Token inválido/expirado é tratado
- [ ] Nova senha permite login
- [ ] Senha antiga deixa de funcionar

## Fluxos principais
- [ ] Feed funcionando
- [ ] Novo desabafo funcionando
- [ ] Post vazio é bloqueado
- [ ] Post longo é bloqueado com mensagem amigável
- [ ] Tags emocionais funcionando
- [ ] Texto do Dia aparece
- [ ] Filtro sensível aciona aviso
- [ ] Página de ajuda abre e mostra CVV 188
- [ ] ECHO funciona sem duplicidade
- [ ] Curtidas/interações não duplicam
- [ ] Reports funcionam
- [ ] Perfil funciona
- [ ] Editar perfil funciona
- [ ] Usuário comum não acessa admin
- [ ] Admin acessa painel e moderação

## Navbar/logo
- [ ] Logo não parece imagem quadrada
- [ ] Logo funciona no mobile
- [ ] Logo funciona no desktop
- [ ] Navbar não quebra
- [ ] Navbar não gera scroll horizontal
- [ ] Links públicos e logados funcionam

## Depois do deploy
- [ ] Testar cadastro real
- [ ] Confirmar email real
- [ ] Testar recuperação de senha real
- [ ] Testar login real
- [ ] Criar post
- [ ] Criar post sensível e confirmar aviso de ajuda
- [ ] Dar e remover ECHO
- [ ] Editar perfil
- [ ] Subir foto
- [ ] Testar mobile
- [ ] Testar página de ajuda
- [ ] Testar política de privacidade e termos
- [ ] Testar admin
- [ ] Conferir cookies seguros em HTTPS
- [ ] Conferir logs sem expor dados sensíveis
- [ ] Confirmar que novos dados persistem no PostgreSQL
