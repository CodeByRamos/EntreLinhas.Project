from flask import Blueprint, render_template, redirect, url_for, session, current_app, Response

import database as db

main = Blueprint('main', __name__)

# Páginas públicas que devem ser indexadas (entram no sitemap).
_SITEMAP_PAGES = ['/', '/sobre', '/feed', '/apoio', '/como-funciona', '/pulso',
                  '/privacidade', '/termos']


@main.route('/robots.txt')
def robots():
    base = (current_app.config.get('APP_BASE_URL', '') or '').rstrip('/')
    lines = [
        "User-agent: *",
        "Allow: /",
        # Áreas privadas/dinâmicas não devem ser indexadas:
        "Disallow: /admin",
        "Disallow: /api",
        "Disallow: /notificacoes",
        "Disallow: /perfil",
        "Disallow: /meus-posts",
        "Disallow: /cartas/desconhecidos/ler",
        f"Sitemap: {base}/sitemap.xml",
        "",
    ]
    return Response("\n".join(lines), mimetype="text/plain")


@main.route('/sitemap.xml')
def sitemap():
    base = (current_app.config.get('APP_BASE_URL', '') or '').rstrip('/')
    items = []
    for path in _SITEMAP_PAGES:
        freq = "daily" if path in ("/feed", "/pulso", "/") else "weekly"
        prio = "1.0" if path == "/" else "0.7"
        items.append(
            f"<url><loc>{base}{path}</loc><changefreq>{freq}</changefreq>"
            f"<priority>{prio}</priority></url>"
        )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + "".join(items)
        + "</urlset>"
    )
    return Response(xml, mimetype="application/xml")


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
