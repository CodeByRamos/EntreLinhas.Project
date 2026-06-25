"""SEO: robots.txt, sitemap.xml e meta tags."""


def test_robots_txt(client):
    r = client.get("/robots.txt")
    assert r.status_code == 200
    assert r.mimetype == "text/plain"
    body = r.get_data(as_text=True)
    assert "Sitemap:" in body
    assert "Disallow: /admin" in body
    assert "Disallow: /api" in body


def test_sitemap_xml(client):
    r = client.get("/sitemap.xml")
    assert r.status_code == 200
    assert "xml" in r.mimetype
    body = r.get_data(as_text=True)
    assert "<urlset" in body
    assert "/sobre" in body and "/pulso" in body


def test_home_has_seo_meta(client):
    body = client.get("/").get_data(as_text=True)
    assert 'name="description"' in body
    assert 'property="og:title"' in body
    assert 'property="og:image"' in body
    assert 'rel="canonical"' in body
    assert 'application/ld+json' in body
    assert "EntreLinhas" in body
    # descrição específica da landing (não a default)
    assert "plataforma anônima e acolhedora" in body


def test_admin_not_indexable_via_robots(client):
    body = client.get("/robots.txt").get_data(as_text=True)
    for path in ["/admin", "/api", "/notificacoes", "/perfil"]:
        assert f"Disallow: {path}" in body
