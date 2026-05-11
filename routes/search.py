from flask import Blueprint, render_template, request, jsonify, current_app
import database as db
from utils.mood_styles import EMOTIONAL_TAG_LABELS

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
        
        return render_template('search.html', 
                              query=query,
                              desabafos=desabafos,
                              emotional_tag_labels=EMOTIONAL_TAG_LABELS,
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
        
        results = []
        for post in desabafos:
            post_id = post['id']
            results.append({
                'id': post['id'],
                'mensagem': post['mensagem'],
                'categoria': post['categoria'],
                'emotional_tag': post['emotional_tag'] if 'emotional_tag' in post.keys() else 'vazio',
                'data_postagem': post['data_postagem'],
                'comments': [dict(comment) for comment in (db.get_comments(post_id) or [])],
                'reaction_counts': db.get_reaction_counts(post_id) or {}
            })
        
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
