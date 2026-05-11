from flask import Blueprint, request, jsonify, redirect, url_for
import database as db

search = Blueprint('search', __name__)


@search.route('/pesquisar')
def pesquisar():
    """Pesquisa visual desativada nesta versão do produto."""
    return redirect(url_for('posts.feed'))


@search.route('/api/pesquisar')
def api_pesquisar():
    """API preservada para uso futuro, sem exposição na interface."""
    try:
        query = request.args.get('q', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 5

        if not query:
            return jsonify({
                'query': '',
                'results': [],
                'page': 1,
                'total_pages': 0,
                'total_results': 0
            })

        offset = (page - 1) * per_page
        desabafos = db.search_posts(query, limit=per_page, offset=offset)
        total_posts = db.count_search_results(query)
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
    except Exception:
        return jsonify({
            'error': 'Não conseguimos buscar agora.',
            'query': request.args.get('q', ''),
            'results': [],
            'page': 1,
            'total_pages': 0,
            'total_results': 0
        }), 500
