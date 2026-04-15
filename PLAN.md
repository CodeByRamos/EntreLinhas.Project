## Plano de Melhorias e Novas Funcionalidades para o Fórum de Desabafos Anônimos

Este documento detalha o plano para aprimorar o projeto "Entre Linhas", um fórum de desabafos anônimos desenvolvido com Flask, HTML, CSS e SQLite3. O objetivo é criar um espaço mais acolhedor, funcional e visualmente atraente, incorporando as funcionalidades solicitadas pelo usuário.

### 1. Análise da Estrutura Atual

O projeto atual consiste em:

*   **`app.py`**: O arquivo principal da aplicação Flask, contendo a lógica de roteamento, manipulação de banco de dados e renderização de templates.
*   **`init_db.py`**: Um script separado para inicializar o banco de dados SQLite (`entrelinhas.db`).
*   **`entrelinhas.db`**: O banco de dados SQLite, que atualmente possui uma tabela `posts` para armazenar os desabafos.
*   **`templates/`**: Contém os arquivos HTML (`home.HTML` e `feed.html`).
*   **`static/css/estilos.css`**: Arquivo CSS para estilos personalizados.
*   **`static/`**: Diretório para arquivos estáticos.

A tabela `posts` no banco de dados, conforme observado em `init_db.py`, possui as seguintes colunas:

*   `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
*   `mensagem` (TEXT NOT NULL)
*   `data_postagem` (TEXT NOT NULL)
*   `categoria` (TEXT)
*   `reacoes` (INTEGER DEFAULT 0)
*   `visivel` (INTEGER DEFAULT 1)

Foi notada uma inconsistência entre a definição da tabela `posts` em `app.py` e `init_db.py`. A versão em `init_db.py` é mais completa, incluindo a coluna `reacoes`. A versão em `init_db.py` será considerada a fonte da verdade e `app.py` será atualizado para refletir essa estrutura.

O arquivo `home.HTML` atualmente redireciona imediatamente para `/feed`, o que será alterado para criar uma página inicial adequada. O `feed.html` já utiliza Tailwind CSS, o que será aproveitado para as melhorias visuais.

### 2. Melhorias e Novas Funcionalidades

As seguintes melhorias e funcionalidades serão implementadas:

#### 2.1. Página Inicial (Home)

*   **Propósito**: Criar uma página de boas-vindas que introduza o conceito do fórum de desabafos anônimos.
*   **Conteúdo**: Texto acolhedor, explicação breve do propósito do site, e um botão claro para navegar para a página de desabafos (`/feed`).
*   **Design**: Utilizar Tailwind CSS para um design moderno, limpo e responsivo, transmitindo uma sensação de acolhimento e segurança.
*   **Arquivo**: `templates/home.html` (será reescrito).

#### 2.2. Melhoria da Página de Desabafos (Feed)

*   **Visual**: Aprimorar o design existente utilizando mais recursos do Tailwind CSS para melhorar a legibilidade, espaçamento e a estética geral dos desabafos e do formulário de envio.
*   **Funcionalidade**: Integrar os sistemas de comentários e reações de forma intuitiva. Considerar a adição de um mecanismo de carregamento de desabafos (e.g., paginação ou carregamento infinito) se o volume de dados justificar.
*   **Arquivo**: `templates/feed.html` (será modificado).

#### 2.3. Sistema de Comentários Anônimos

*   **Funcionalidade**: Permitir que os usuários comentem anonimamente em cada desabafo.
*   **Estrutura do Banco de Dados**: Será criada uma nova tabela `comments`.
    *   `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
    *   `post_id` (INTEGER, FOREIGN KEY para `posts.id`)
    *   `comment_text` (TEXT NOT NULL)
    *   `data_comentario` (TEXT NOT NULL)
    *   `visivel` (INTEGER DEFAULT 1)
*   **Backend**: Rota Flask para receber e armazenar comentários. Função para recuperar comentários associados a um desabafo específico.
*   **Frontend**: Formulário de comentário abaixo de cada desabafo. Exibição dos comentários de forma organizada. Utilização de JavaScript (AJAX) para submissão de comentários sem recarregar a página.

#### 2.4. Sistema de Reações aos Desabafos

*   **Funcionalidade**: Permitir que os usuários reajam aos desabafos com opções predefinidas (ex: “te entendo”, “força!”, “abraço virtual”).
*   **Estrutura do Banco de Dados**: Será criada uma nova tabela `reactions`.
    *   `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
    *   `post_id` (INTEGER, FOREIGN KEY para `posts.id`)
    *   `reaction_type` (TEXT NOT NULL, e.g., 'te_entendo', 'forca', 'abraco_virtual')
    *   `data_reacao` (TEXT NOT NULL)
*   **Backend**: Rota Flask para registrar reações. Função para atualizar e recuperar a contagem de cada tipo de reação para um desabafo.
*   **Frontend**: Botões de reação visíveis em cada desabafo. Exibição da contagem de cada reação. Utilização de JavaScript (AJAX) para registrar reações sem recarregar a página.

#### 2.5. Páginas Adicionais

*   **Propósito**: Fornecer informações adicionais sobre o site e seu funcionamento.
*   **Páginas**: `Sobre o site` (`templates/about.html`) e `Como funciona` (`templates/how_it_works.html`).
*   **Conteúdo**: Textos informativos e explicativos.
*   **Design**: Seguir o mesmo padrão visual das demais páginas, utilizando Tailwind CSS.

### 3. Estrutura do Código (Modularização com Blueprints)

Para garantir um código limpo, organizado e escalável, a aplicação será reestruturada utilizando Flask Blueprints. A nova estrutura de diretórios será:

```
EntreLinhas Project/
├── app.py                  # Configuração principal da aplicação e registro de Blueprints
├── config.py               # Variáveis de configuração (e.g., SECRET_KEY, DB_PATH)
├── database.py             # Funções centralizadas para conexão e inicialização do banco de dados
├── init_db.py              # Script para inicialização do banco de dados (mantido para referência)
├── entrelinhas.db          # Banco de dados SQLite
├── routes/                 # Contém os Blueprints para diferentes seções da aplicação
│   ├── __init__.py
│   ├── main.py             # Rotas para a página inicial, sobre, como funciona
│   ├── posts.py            # Rotas para desabafos (feed, envio)
│   ├── comments.py         # Rotas para comentários
│   └── reactions.py        # Rotas para reações
├── templates/              # Arquivos HTML
│   ├── base.html           # Template base para elementos comuns (cabeçalho, rodapé, navegação)
│   ├── home.html           # Nova página inicial
│   ├── feed.html           # Página de desabafos atualizada
│   ├── about.html          # Página 'Sobre o site'
│   └── how_it_works.html   # Página 'Como funciona'
└── static/
    ├── css/
    │   └── estilos.css     # CSS personalizado (além do Tailwind)
    └── js/
        ├── main.js         # JavaScript geral
        ├── comments.js     # JavaScript para funcionalidades de comentários
        └── reactions.js    # JavaScript para funcionalidades de reações
```

### 4. Tecnologias e Ferramentas

*   **Backend**: Flask (Python)
*   **Banco de Dados**: SQLite3
*   **Frontend**: HTML5, CSS3 (com Tailwind CSS), JavaScript
*   **Modularização**: Flask Blueprints

### 5. Próximos Passos

1.  **Atualizar o esquema do banco de dados**: Modificar `init_db.py` e `app.py` para incluir as novas tabelas `comments` e `reactions`, e ajustar a tabela `posts` se necessário.
2.  **Reestruturar o projeto**: Criar os diretórios e arquivos conforme a nova estrutura de Blueprints.
3.  **Implementar a página inicial**: Desenvolver o novo `home.html` e a rota correspondente.
4.  **Refatorar a página de desabafos**: Adaptar `feed.html` para a nova estrutura e preparar para a integração de comentários e reações.
5.  **Desenvolver o sistema de comentários**: Implementar backend e frontend.
6.  **Desenvolver o sistema de reações**: Implementar backend e frontend.
7.  **Criar páginas adicionais**: Desenvolver `about.html` e `how_it_works.html`.
8.  **Testes**: Realizar testes completos de todas as funcionalidades.
9.  **Documentação**: Garantir que o código esteja bem comentado e que a documentação seja clara.





### 6. Melhorias Futuras e Novas Funcionalidades (Versão 2.0)

Com base nas sugestões de melhorias futuras e na solicitação de adicionar ainda mais funcionalidades, o projeto "Entre Linhas" será expandido para incluir os seguintes recursos:

#### 6.1. Sistema de Moderação para Conteúdo Inadequado

*   **Propósito**: Garantir um ambiente seguro e acolhedor, filtrando e removendo conteúdo que viole as diretrizes da comunidade (linguagem ofensiva, discurso de ódio, etc.).
*   **Abordagem**: Implementar um sistema de moderação manual inicial, onde desabafos e comentários podem ser marcados como "visivel=0" no banco de dados. Futuramente, pode-se considerar a integração com APIs de moderação de conteúdo ou a implementação de um sistema de denúncias por parte dos usuários.
*   **Impacto no Banco de Dados**: A coluna `visivel` já existe nas tabelas `posts` e `comments` e será utilizada para este fim.
*   **Backend**: Rotas administrativas para visualizar e gerenciar conteúdo marcado. Funções no `database.py` para atualizar o status de visibilidade.
*   **Frontend**: Interface simples para administradores (ou para o próprio usuário que postou, se for o caso de um perfil anônimo) marcarem conteúdo como inadequado. Por enquanto, será uma funcionalidade de backend/admin.

#### 6.2. Filtragem de Desabafos por Categoria

*   **Propósito**: Permitir que os usuários visualizem desabafos de categorias específicas, facilitando a navegação e a busca por tópicos de interesse.
*   **Backend**: Modificar a função `get_posts` em `database.py` para aceitar um parâmetro de categoria. Nova rota no Blueprint `posts` para lidar com a filtragem.
*   **Frontend**: Adicionar um menu de seleção ou botões de filtro na página `feed.html` para que os usuários possam escolher a categoria desejada. Atualização dinâmica da lista de desabafos via JavaScript (AJAX) ou recarregamento da página.

#### 6.3. Paginação de Desabafos

*   **Propósito**: Melhorar a performance e a usabilidade da página de desabafos, especialmente com um grande volume de posts, dividindo-os em páginas.
*   **Backend**: Modificar a função `get_posts` em `database.py` para aceitar parâmetros de `offset` e `limit`. Adicionar lógica para calcular o número total de páginas e a página atual. Nova rota no Blueprint `posts` para lidar com a paginação.
*   **Frontend**: Implementar controles de paginação (botões "Anterior", "Próximo", números de página) na parte inferior da página `feed.html`. Atualização da lista de desabafos ao navegar entre as páginas.

#### 6.4. Persistência do Modo Escuro/Claro

*   **Propósito**: Salvar a preferência do usuário pelo modo escuro ou claro, para que a escolha seja mantida entre as sessões e ao navegar pelo site.
*   **Frontend**: Utilizar `localStorage` do navegador para armazenar a preferência do usuário. Modificar `main.js` para ler e aplicar essa preferência ao carregar a página e para atualizar `localStorage` quando o usuário alternar o tema.
*   **UI**: Adicionar um botão de alternância de tema (sol/lua) na interface, provavelmente no cabeçalho ou rodapé.

#### 6.5. Estatísticas Anônimas

*   **Propósito**: Fornecer insights sobre os temas mais discutidos e as reações mais populares, sem comprometer o anonimato dos usuários.
*   **Backend**: Novas funções em `database.py` para consultar:
    *   Contagem de desabafos por categoria.
    *   Contagem total de comentários e reações.
    *   Tipos de reações mais utilizados.
*   **Frontend**: Criar uma nova página (`templates/statistics.html`) ou uma seção na página inicial/sobre para exibir essas estatísticas de forma visualmente atraente (e.g., gráficos simples, barras de progresso). Pode-se usar uma biblioteca JavaScript para gráficos se necessário.

#### 6.6. Pesquisa de Desabafos

*   **Propósito**: Permitir que os usuários busquem desabafos por palavras-chave no conteúdo da mensagem.
*   **Backend**: Nova função em `database.py` para realizar buscas na tabela `posts` usando `LIKE` ou Full-Text Search (se o volume de dados justificar uma solução mais robusta).
*   **Frontend**: Adicionar um campo de busca na página `feed.html` (ou em uma nova página de busca). Exibir os resultados da busca de forma clara.

#### 6.7. Melhoria da Experiência de Postagem

*   **Contador de Caracteres**: Adicionar um contador de caracteres ao `textarea` do formulário de desabafo para guiar o usuário sobre o tamanho da mensagem.
*   **Validação Frontend**: Implementar validação básica no lado do cliente (JavaScript) para garantir que o campo de desabafo não esteja vazio e que uma categoria seja selecionada antes do envio, proporcionando feedback instantâneo ao usuário.
*   **Arquivo**: Modificações em `feed.html` e `main.js` (ou um novo arquivo `post_form.js`).

#### 6.8. Página de Perfil Anônimo (Conceito)

*   **Propósito**: Permitir que um usuário visualize todos os desabafos e comentários que ele mesmo fez, mantendo o anonimato em relação a outros usuários. Isso seria feito através de um identificador único e persistente no navegador (e.g., um cookie ou `localStorage`), sem vincular a nenhuma informação pessoal.
*   **Abordagem**: Esta é uma funcionalidade mais complexa que requer um identificador de sessão anônimo. Cada desabafo e comentário seria associado a este ID. O usuário poderia ver um "seu perfil" que lista apenas o conteúdo que ele criou com aquele ID de sessão.
*   **Impacto no Banco de Dados**: Adicionar uma coluna `user_session_id` (TEXT) às tabelas `posts` e `comments`.
*   **Backend**: Rotas para `meus_desabafos` e `meus_comentarios` que filtram pelo `user_session_id`. Lógica para gerar e gerenciar este ID.
*   **Frontend**: Nova página (`templates/my_anonymous_profile.html`) para exibir o conteúdo do usuário. Botão "Meu Perfil" na navegação.

### 7. Reestruturação e Refatoração Adicionais

*   **Refatoração de `database.py`**: Separar as funções de CRUD em módulos menores ou classes para melhor organização, especialmente com o aumento do número de tabelas e operações.
*   **Tratamento de Erros**: Melhorar o tratamento de erros em todas as rotas e funções do backend, fornecendo mensagens mais informativas e registrando logs.
*   **Testes Unitários**: Implementar testes unitários para as funções do `database.py` e para as rotas da API.

### 8. Próximos Passos Detalhados

1.  **Moderação**: Adicionar a funcionalidade de moderação (visibilidade) via backend.
2.  **Filtragem por Categoria**: Implementar a filtragem no backend e frontend.
3.  **Paginação**: Implementar a paginação no backend e frontend.
4.  **Modo Escuro/Claro Persistente**: Adicionar a lógica de `localStorage` e o botão de alternância.
5.  **Estatísticas**: Criar a página de estatísticas e as consultas no banco de dados.
6.  **Pesquisa**: Implementar a funcionalidade de busca.
7.  **Melhorias na Postagem**: Adicionar contador de caracteres e validação frontend.
8.  **Perfil Anônimo**: Implementar o conceito de perfil anônimo.
9.  **Refatoração**: Realizar refatorações de código conforme necessário.
10. **Testes Abrangentes**: Testar todas as novas funcionalidades.





## 🟠 FASE 3 – Moderação e Karma

### 8. Reportar post

Para implementar a funcionalidade de reportar posts, será adicionado um botão "Reportar" em cada desabafo. Ao clicar neste botão, será registrada uma entrada em uma nova tabela `reports` no banco de dados. Esta tabela terá os campos `id`, `post_id` (referenciando o desabafo reportado) e `data` (registrando quando o report foi feito). Será implementada uma lógica para verificar a quantidade de reports que um post recebe. Se um desabafo atingir um número predefinido de reports (por exemplo, 5 ou mais), ele será automaticamente marcado como `visivel = false`, tornando-o invisível para os usuários comuns no feed, mas ainda acessível para moderação no painel administrativo.

### 9. Karma de comentários

Para promover a qualidade dos comentários e dar visibilidade a respostas úteis e empáticas, será implementado um sistema de "karma" para comentários. Cada comentário terá botões de 👍 (positivo) e 👎 (negativo). O karma de um comentário será a soma das reações positivas menos as negativas. Comentários que atingirem um karma de +10 (ou outro valor definido) receberão um destaque visual, indicando que são "apoio confiável". Isso incentivará os usuários a fornecerem respostas construtivas e solidárias.

## 🟣 FASE 4 – UX, Visual e Extras

### 11. Filtros de visualização

Serão adicionados filtros de visualização na página de desabafos para melhorar a experiência do usuário. Além do filtro por categoria já existente, será implementado um filtro por ordem, permitindo que os usuários visualizem os desabafos mais recentes ou os mais apoiados (com base no número de reações positivas). Isso dará mais controle ao usuário sobre como ele deseja consumir o conteúdo do fórum.

### Melhoria Visual do Site

O visual geral do site será modernizado. Isso inclui a seleção de fontes mais agradáveis e menos genéricas, ajustes na paleta de cores para um visual mais coeso e acolhedor, e refinamentos no layout para garantir uma estética limpa e contemporânea. O objetivo é criar uma interface que seja visualmente atraente e que transmita a sensação de um espaço seguro e confortável.

### Contas Permanentes e Lógica de Desabafos

O sistema de "perfil anônimo" será refatorado para permitir a criação de contas permanentes. Isso significa que os usuários poderão criar um login (sem a necessidade de e-mail ou informações pessoais, mantendo o anonimato, mas com um identificador persistente) e acessar seu perfil de qualquer dispositivo. A lógica de desabafos será atualizada para exigir que o usuário esteja logado em uma conta permanente para poder criar novos desabafos. Isso ajudará a manter a integridade da plataforma e a rastrear o conteúdo de forma mais eficaz para fins de moderação, sem comprometer o anonimato do usuário.

