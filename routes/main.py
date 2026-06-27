import json

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


@main.route('/manifest.webmanifest')
def manifest():
    """Web App Manifest: torna o EntreLinhas instalável no celular (PWA).

    Servido por rota (e não como estático) para garantir o MIME correto. Ícones
    em caminhos absolutos a partir da raiz — resolvem certo independentemente de
    onde o manifest vive.
    """
    data = {
        "name": "EntreLinhas",
        "short_name": "EntreLinhas",
        "description": "Um espaço anônimo e acolhedor para desabafar e ser ouvido, sem julgamento.",
        "lang": "pt-BR",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#0a0e16",
        "theme_color": "#0a0e16",
        "categories": ["health", "lifestyle", "social"],
        "icons": [
            {"src": "/static/images/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "/static/images/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
            {"src": "/static/images/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
        ],
    }
    return Response(json.dumps(data, ensure_ascii=False), mimetype="application/manifest+json")


@main.route('/sw.js')
def service_worker():
    """Service worker mínimo (pass-through) servido da RAIZ para ter escopo '/'.

    Só habilita a instalação do PWA (o Chrome exige um handler de fetch). NÃO faz
    cache — deixa o navegador lidar com tudo normalmente, então nunca serve
    conteúdo obsoleto. Offline fica para depois, se fizer sentido.
    """
    js = (
        "self.addEventListener('install', function(){ self.skipWaiting(); });\n"
        "self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });\n"
        "self.addEventListener('fetch', function(){ /* sem cache: navegador decide */ });\n"
    )
    resp = Response(js, mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


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
