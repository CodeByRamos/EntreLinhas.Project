from flask import Blueprint, render_template, jsonify
import database as db

# Criação do Blueprint para as rotas de estatísticas
stats = Blueprint('stats', __name__)

@stats.route('/estatisticas')
def estatisticas():
    """Rota para a página de estatísticas."""
    # Obter estatísticas do banco de dados
    post_stats = db.get_post_stats()
    comment_stats = db.get_comment_stats()
    reaction_stats = db.get_reaction_stats()
    
    return render_template('stats.html', 
                          post_stats=post_stats,
                          comment_stats=comment_stats,
                          reaction_stats=reaction_stats)

@stats.route('/api/estatisticas')
def api_estatisticas():
    """Rota para API de estatísticas (para uso com JavaScript)."""
    # Obter estatísticas do banco de dados
    post_stats = db.get_post_stats()
    comment_stats = db.get_comment_stats()
    reaction_stats = db.get_reaction_stats()
    
    # Formatar dados para gráficos
    chart_data = {
        'posts_by_category': {
            'labels': [cat['categoria'] for cat in post_stats['posts_by_category']],
            'data': [cat['count'] for cat in post_stats['posts_by_category']]
        },
        'posts_by_weekday': {
            'labels': [day['dia_semana'] for day in post_stats['posts_by_weekday']],
            'data': [day['count'] for day in post_stats['posts_by_weekday']]
        },
        'posts_by_hour': {
            'labels': [f"{hour['hora']}h" for hour in post_stats['posts_by_hour']],
            'data': [hour['count'] for hour in post_stats['posts_by_hour']]
        },
        'reactions_by_type': {
            'labels': [r['reaction_type'] for r in reaction_stats['reactions_by_type']],
            'data': [r['count'] for r in reaction_stats['reactions_by_type']]
        }
    }
    
    return jsonify({
        'post_stats': post_stats,
        'comment_stats': comment_stats,
        'reaction_stats': reaction_stats,
        'chart_data': chart_data
    })

