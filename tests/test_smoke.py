"""Renderização das páginas — nenhuma deve dar 500."""
import pytest


PUBLIC = ["/", "/feed", "/sobre", "/apoio", "/como-funciona", "/pulso",
          "/login", "/registro", "/admin/login", "/privacidade", "/termos"]


@pytest.mark.parametrize("url", PUBLIC)
def test_public_pages_ok(client, url):
    r = client.get(url)
    assert r.status_code in (200, 302), f"{url} -> {r.status_code}"


LOGGED = ["/feed", "/meus-posts", "/superacoes", "/linha-do-tempo",
          "/cartas", "/cartas/desconhecidos", "/acolher", "/notificacoes", "/perfil"]


@pytest.mark.parametrize("url", LOGGED)
def test_logged_pages_ok(logged_client, url):
    r = logged_client.get(url)
    assert r.status_code == 200, f"{url} -> {r.status_code}"


def test_admin_pages_ok(admin_client):
    for url in ["/admin/", "/admin/moderacao", "/admin/usuarios",
                "/admin/posts", "/admin/psicologos", "/admin/reports"]:
        r = admin_client.get(url)
        assert r.status_code == 200, f"{url} -> {r.status_code}"


def test_404_page(client):
    assert client.get("/rota-que-nao-existe-xyz").status_code == 404
