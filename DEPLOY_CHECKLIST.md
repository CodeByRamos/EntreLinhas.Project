# Checklist de Deploy — EntreLinhas

## Antes do deploy
- [ ] Debug desligado
- [ ] `SECRET_KEY` configurada
- [ ] `DATABASE_URL` configurada com PostgreSQL
- [ ] URL `postgres://` normalizada ou aceita como `postgresql://`
- [ ] `flask db upgrade` executado
- [ ] SQLite não está sendo usado como banco principal em produção
- [ ] `STORAGE_PROVIDER` configurado como `cloudinary` ou `s3`
- [ ] Uploads testados no storage persistente
- [ ] Admin criado
- [ ] Static files carregando
- [ ] Logo SVG carregando corretamente
- [ ] Login funcionando
- [ ] Cadastro funcionando
- [ ] Feed funcionando
- [ ] Novo desabafo funcionando
- [ ] Filtro sensível acionando aviso
- [ ] ECHO funcionando
- [ ] Perfil funcionando
- [ ] Editar perfil funcionando
- [ ] Ajuda funcionando
- [ ] Privacidade e Termos publicados
- [ ] Reports funcionando
- [ ] Página 404 testada
- [ ] Página 500 revisada
- [ ] QA em dispositivo físico executado

## Depois do deploy
- [ ] Testar cadastro real
- [ ] Testar login real
- [ ] Criar post
- [ ] Criar post sensível e confirmar aviso de ajuda
- [ ] Dar e remover ECHO
- [ ] Editar perfil
- [ ] Subir foto
- [ ] Confirmar que upload persiste após redeploy
- [ ] Testar mobile
- [ ] Testar página de ajuda
- [ ] Testar política de privacidade e termos
- [ ] Testar admin
- [ ] Conferir cookies seguros em HTTPS
- [ ] Conferir logs sem expor dados sensíveis
- [ ] Confirmar que novos dados persistem no PostgreSQL
