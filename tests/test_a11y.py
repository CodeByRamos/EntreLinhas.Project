"""Testes de acessibilidade (axe-core) contra um servidor ao vivo.

Sobe o app real numa thread e roda o axe nas páginas públicas via Playwright.
Falha se houver violação de impacto `serious` ou `critical`.

Auto-pula se playwright / axe-core-python / o navegador não estiverem instalados
(assim `pytest` normal segue verde para quem não roda a suíte de a11y). No CI o
workflow instala tudo e o teste roda de verdade.
"""
import socket
import threading

import pytest

pytest.importorskip("playwright.sync_api")
pytest.importorskip("axe_core_python")

from werkzeug.serving import make_server  # noqa: E402
import app as appmod  # noqa: E402

PUBLIC_PAGES = ["/", "/feed", "/login", "/registro", "/apoio", "/sobre", "/como-funciona"]
BLOCKING_IMPACTS = {"serious", "critical"}


@pytest.fixture(scope="module")
def live_server():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = make_server("127.0.0.1", port, appmod.app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()


def test_no_serious_accessibility_violations(live_server):
    from playwright.sync_api import sync_playwright
    from axe_core_python.sync_playwright import Axe

    axe = Axe()
    failures = []
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except Exception as exc:  # navegador não instalado (ex.: sem `playwright install`)
            pytest.skip(f"Chromium indisponível: {exc}")
        page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
        for path in PUBLIC_PAGES:
            page.goto(live_server + path, wait_until="networkidle")
            page.wait_for_timeout(250)
            result = axe.run(page)
            for violation in result["violations"]:
                if violation.get("impact") in BLOCKING_IMPACTS:
                    failures.append(
                        f"{path}: [{violation['impact']}] {violation['id']} "
                        f"({len(violation['nodes'])}x) — {violation['help']}"
                    )
        browser.close()

    assert not failures, "Violações de acessibilidade encontradas:\n" + "\n".join(failures)
