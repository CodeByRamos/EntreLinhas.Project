# Entre Linhas - Fórum de Desabafos Anônimos

## Sobre o Projeto

Entre Linhas é um fórum de desabafos anônimos desenvolvido com Flask, HTML, CSS e SQLite3. O objetivo é criar um espaço acolhedor onde usuários possam compartilhar seus pensamentos e sentimentos de forma anônima, além de interagir com os relatos de outras pessoas através de comentários e reações.

## Funcionalidades

### Funcionalidades Base
- **Página inicial** acolhedora com introdução ao propósito do site
- **Feed de desabafos** com design responsivo e intuitivo
- **Sistema de comentários anônimos** para cada desabafo
- **Sistema de reações** personalizadas ("te entendo", "força!", "abraço virtual")
- **Páginas informativas** como "Sobre o site" e "Como funciona"

### Novas Funcionalidades
- **Sistema de moderação** para conteúdo inadequado
- **Filtragem de desabafos por categoria** para facilitar a navegação
- **Paginação** para melhor organização dos desabafos
- **Persistência do modo escuro/claro** para melhor experiência do usuário
- **Estatísticas anônimas** sobre o uso da plataforma
- **Pesquisa de desabafos** por palavras-chave
- **Contador de caracteres e validação** para melhorar a experiência de postagem
- **Perfil anônimo** para acompanhar seus desabafos e comentários

## Estrutura do Projeto

```
EntreLinhas Project/
├── app.py                  # Arquivo principal da aplicação
├── config.py               # Configurações da aplicação
├── database.py             # Funções de acesso ao banco de dados
├── init_db.py              # Script para inicializar o banco de dados
├── entrelinhas.db          # Banco de dados SQLite
├── static/                 # Arquivos estáticos
│   ├── css/                # Estilos CSS
│   │   └── estilos.css     # Estilos personalizados
│   └── js/                 # Scripts JavaScript
│       ├── comments.js     # Funcionalidades de comentários
│       ├── main.js         # Script principal
│       ├── post-form.js    # Validação do formulário de postagem
│       ├── reactions.js    # Funcionalidades de reações
│       └── theme.js        # Gerenciamento de tema claro/escuro
├── templates/              # Templates HTML
│   ├── base.html           # Template base
│   ├── home.html           # Página inicial
│   ├── feed.html           # Feed de desabafos
│   ├── about.html          # Página "Sobre"
│   ├── how_it_works.html   # Página "Como funciona"
│   ├── search.html         # Página de pesquisa
│   ├── stats.html          # Página de estatísticas
│   ├── admin/              # Templates de administração
│   │   ├── base.html       # Template base para admin
│   │   ├── login.html      # Página de login
│   │   ├── dashboard.html  # Dashboard administrativo
│   │   ├── posts.html      # Gerenciamento de posts
│   │   └── comments.html   # Gerenciamento de comentários
│   └── profile/            # Templates de perfil anônimo
│       ├── create.html     # Criação de perfil
│       ├── view.html       # Visualização de perfil
│       ├── edit.html       # Edição de perfil
│       ├── posts.html      # Posts do perfil
│       └── comments.html   # Comentários do perfil
└── routes/                 # Rotas da aplicação
    ├── __init__.py         # Inicialização do pacote
    ├── main.py             # Rotas principais
    ├── posts.py            # Rotas para posts
    ├── comments.py         # Rotas para comentários
    ├── reactions.py        # Rotas para reações
    ├── admin.py            # Rotas administrativas
    ├── stats.py            # Rotas para estatísticas
    ├── search.py           # Rotas para pesquisa
    └── profile.py          # Rotas para perfil anônimo
```

## Tecnologias Utilizadas

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Banco de Dados**: SQLite3
- **CSS Framework**: Tailwind CSS (via CDN)
- **Ícones**: Heroicons

## Instalação e Execução

1. Clone o repositório:
```
git clone <url-do-repositorio>
```

2. Navegue até o diretório do projeto:
```
cd EntreLinhas
```

3. Instale as dependências:
```
pip install flask
```

4. Inicialize o banco de dados:
```
python init_db.py
```

5. Execute a aplicação:
```
python app.py
```

6. Acesse a aplicação em seu navegador:
```
http://localhost:5000
```

## Melhorias Implementadas

### 1. Sistema de Moderação
- Painel administrativo para gerenciar conteúdo
- Filtro de conteúdo inadequado
- Possibilidade de ocultar posts e comentários

### 2. Filtragem por Categoria
- Categorias para organizar os desabafos (trabalho, relacionamentos, família, etc.)
- Interface intuitiva para filtrar por categoria
- Badges coloridas para identificar categorias

### 3. Paginação
- Navegação eficiente entre páginas de desabafos
- Controle de quantidade de itens por página
- Indicadores visuais de página atual

### 4. Tema Escuro/Claro
- Alternância entre temas claro e escuro
- Persistência da preferência do usuário via localStorage
- Design responsivo para ambos os temas

### 5. Estatísticas Anônimas
- Visualização de dados sobre uso da plataforma
- Gráficos de categorias mais populares
- Contagem de desabafos e comentários

### 6. Sistema de Pesquisa
- Busca por palavras-chave nos desabafos
- Resultados organizados por relevância
- Interface amigável para pesquisa

### 7. Melhorias na Experiência de Postagem
- Contador de caracteres em tempo real
- Validação de formulários
- Feedback visual durante a digitação

### 8. Perfil Anônimo
- Criação de perfil sem necessidade de e-mail ou senha
- Acompanhamento de desabafos e comentários próprios
- Personalização com apelido e bio

## Próximos Passos

Algumas sugestões para futuras melhorias:

1. **Notificações**: Sistema para notificar usuários sobre novos comentários em seus desabafos
2. **Tags personalizadas**: Permitir que usuários criem tags além das categorias existentes
3. **Compartilhamento**: Opção para compartilhar desabafos em redes sociais
4. **Recursos de acessibilidade**: Melhorar a experiência para usuários com necessidades especiais
5. **Suporte a imagens**: Permitir anexar imagens aos desabafos
6. **Modo offline**: Funcionalidade básica quando sem conexão com a internet
7. **Exportação de dados**: Permitir que usuários baixem seus próprios desabafos e comentários

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para detalhes.

## Contato

Para qualquer dúvida ou sugestão, entre em contato através do e-mail: contato@entrelinhas.com

