"""Apoio ao projeto: página /apoiar, código Pix e selo de Apoiador."""
from utils.pix import build_pix_brcode, _crc16
from utils.roles import ROLE_BADGES, ROLE_ORDER, ROLE_LABELS, get_role_badge


def test_apoiar_page_renders(client):
    r = client.get("/apoiar")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Apoie o EntreLinhas" in body or "manter" in body
    assert "Apoiador" in body  # explica o selo


def test_apoiar_shows_pix_when_configured(client):
    app = client.application
    old = {k: app.config.get(k) for k in ("PIX_KEY", "PIX_RECEIVER_NAME", "PIX_CITY")}
    app.config["PIX_KEY"] = "doacoes@entrelinhas.app"
    app.config["PIX_RECEIVER_NAME"] = "EntreLinhas"
    app.config["PIX_CITY"] = "Sao Paulo"
    try:
        body = client.get("/apoiar").get_data(as_text=True)
        assert "doacoes@entrelinhas.app" in body          # chave aparece
        assert "Pix copia e cola" in body                  # BR Code aparece
        assert "br.gov.bcb.pix" in body                    # payload EMV válido no HTML
    finally:
        for k, v in old.items():
            app.config[k] = v


def test_apoiar_without_pix_is_graceful(client):
    app = client.application
    old = app.config.get("PIX_KEY")
    app.config["PIX_KEY"] = ""
    try:
        r = client.get("/apoiar")
        assert r.status_code == 200
        assert "Em breve" in r.get_data(as_text=True)
    finally:
        app.config["PIX_KEY"] = old


def test_pix_brcode_is_valid():
    code = build_pix_brcode("chave@teste.com", "Fulano de Tal", "Rio de Janeiro")
    assert code.startswith("000201")        # payload format indicator
    assert "br.gov.bcb.pix" in code
    assert "chave@teste.com" in code
    assert _crc16(code[:-4]) == code[-4:]    # CRC16 confere


def test_pix_brcode_empty_without_key():
    assert build_pix_brcode("") == ""
    assert build_pix_brcode(None) == ""


def test_apoiador_badge_exists_and_assignable():
    assert "apoiador" in ROLE_ORDER          # admin pode atribuir
    assert "apoiador" in ROLE_LABELS
    badge = get_role_badge("apoiador")
    assert badge and badge["slug"] == "apoiador" and badge["label"] == "Apoiador"


def test_apoiador_badge_is_in_sitemap_route(client):
    body = client.get("/sitemap.xml").get_data(as_text=True)
    assert "/apoiar" in body
