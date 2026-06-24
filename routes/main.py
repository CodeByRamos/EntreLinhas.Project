from flask import Blueprint, render_template, redirect, url_for, session
import database as db

main = Blueprint('main', __name__)


def _landing_stats():
    """Números reais da comunidade para a prova social (degrada para 0 em erro)."""
    stats = {'desabafos': 0, 'respostas': 0, 'acolhimentos': 0, 'cartas': 0}
    try:
        stats['desabafos'] = db.get_post_count() or 0
    except Exception:
        pass
    try:
        stats['respostas'] = db.get_comment_count() or 0
    except Exception:
        pass
    try:
        stats['acolhimentos'] = db.get_reaction_count() or 0
    except Exception:
        pass
    conn = None
    try:
        conn = db.get_db_connection()
        fl = conn.execute("SELECT COUNT(*) FROM future_letters").fetchone()[0]
        sl = conn.execute("SELECT COUNT(*) FROM stranger_letters").fetchone()[0]
        stats['cartas'] = (fl or 0) + (sl or 0)
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return stats


@main.route('/')
def home():
    # Logado já conhece o produto: vai direto ao feed. Visitante vê a landing.
    if session.get('user_id'):
        return redirect(url_for('posts.feed'))
    return render_template('home.html', stats=_landing_stats())


@main.route('/sobre')
def about():
    return render_template('about.html')


@main.route('/como-funciona')
def how_it_works():
    return render_template('how_it_works.html')


@main.route('/privacidade')
def privacy():
    return render_template('privacy.html')


@main.route('/termos')
def terms():
    return render_template('terms.html')
