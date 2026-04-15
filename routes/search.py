from flask import Blueprint, render_template, request, jsonify, current_app
import database as db

# Criação do Blueprint para as rotas de pesquisa
search = Blueprint('search', __name__)

@search.route('/pesquisar')
def pesquisar():
    """Rota para a página de pesquisa."""
    try:
        # Obter parâmetros de pesquisa e paginação
        query = request.args.get('q', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 5  # Número de posts por página
        
        # Se não houver consulta, retornar página de pesquisa vazia
        if not query:
            return render_template('search.html', 
                                  query='',
                                  desabafos=[],
                                  page=1,
                                  total_pages=0,
                                  total_results=0)
        
        # Calcular o offset para paginação
        offset = (page - 1) * per_page
        
        # Obter resultados da pesquisa
        desabafos = db.search_posts(query, limit=per_page, offset=offset)
        total_posts = db.count_search_results(query)
        
        # Calcular número total de páginas
        total_pages = (total_posts + per_page - 1) // per_page if total_posts > 0 else 0
        
        # Obter categorias e reações da configuração
        categorias = current_app.config.get('CATEGORIAS', [])
        reacoes = current_app.config.get('REACOES', [])
        
        # Preparar dados para cada post
        for post in desabafos:
            try:
                post_id = post['id']
                post['comments'] = db.get_comments(post_id) or []
                post['reaction_counts'] = db.get_reaction_counts(post_id) or {}
            except Exception as e:
                print(f"Erro ao processar post {post.get('id', 'unknown')}: {e}")
                post['comments'] = []
                post['reaction_counts'] = {}
        
        return render_template('search.html', 
                              query=query,
                              desabafos=desabafos,
                              categorias=categorias,
                              reacoes=reacoes,
                              page=page,
                              total_pages=total_pages,
                              total_results=total_posts)
    
    except Exception as e:
        print(f"Erro na pesquisa: {e}")
        return render_template('search.html', 
                              query=request.args.get('q', ''),
                              desabafos=[],
                              page=1,
                              total_pages=0,
                              total_results=0,
                              error="Erro interno do servidor. Tente novamente mais tarde.")

@search.route('/api/pesquisar')
def api_pesquisar():
    """Rota para API de pesquisa (para uso com JavaScript)."""
    try:
        # Obter parâmetros de pesquisa e paginação
        query = request.args.get('q', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 5  # Número de posts por página
        
        # Se não houver consulta, retornar resultados vazios
        if not query:
            return jsonify({
                'query': '',
                'results': [],
                'page': 1,
                'total_pages': 0,
                'total_results': 0
            })
        
        # Calcular o offset para paginação
        offset = (page - 1) * per_page
        
        # Obter resultados da pesquisa
        desabafos = db.search_posts(query, limit=per_page, offset=offset)
        total_posts = db.count_search_results(query)
        
        # Calcular número total de páginas
        total_pages = (total_posts + per_page - 1) // per_page if total_posts > 0 else 0
        
        # Preparar dados para cada post
        results = []
        for post in desabafos:
            try:
                post_id = post['id']
                post_data = {
                    'id': post['id'],
                    'mensagem': post['mensagem'],
                    'categoria': post['categoria'],
                    'data_postagem': post['data_postagem'],
                    'comments': db.get_comments(post_id) or [],
                    'reaction_counts': db.get_reaction_counts(post_id) or {}
                }
                results.append(post_data)
            except Exception as e:
                print(f"Erro ao processar post {post.get('id', 'unknown')}: {e}")
                continue
        
        return jsonify({
            'query': query,
            'results': results,
            'page': page,
            'total_pages': total_pages,
            'total_results': total_posts
        })
    
    except Exception as e:
        print(f"Erro na API de pesquisa: {e}")
        return jsonify({
            'error': 'Erro interno do servidor',
            'query': request.args.get('q', ''),
            'results': [],
            'page': 1,
            'total_pages': 0,
            'total_results': 0
        }), 500

