from utils.sensitive_content import RISK_LOW, RISK_MEDIUM, RISK_HIGH


def build_sensitive_response(risk_level, should_block=False):
    """Resposta de acolhimento para o eixo de risco emocional."""
    if risk_level in (RISK_MEDIUM, RISK_HIGH):
        return {
            "level": risk_level,
            "title": "Um cuidado antes de publicar",
            "message": (
                "Esse desabafo parece carregar uma dor muito pesada. Você pode continuar "
                "escrevendo, mas a gente quer te lembrar de uma coisa importante: você não "
                "precisa passar por isso sozinho."
            ),
            "support_message": (
                "Se existe risco de você se machucar agora, procure ajuda imediatamente. "
                "Ligue 188 para o CVV ou acione 192/190 em caso de emergência."
            ),
            "show_help_contacts": True,
            "allow_continue": not should_block,
            "allow_edit": True,
            "block_reason": (
                "Neste momento, vale respirar e procurar ajuda real antes de publicar. "
                "Você pode editar o texto ou abrir os caminhos de ajuda."
            ) if should_block else "",
        }

    return {
        "level": RISK_LOW,
        "title": "",
        "message": "",
        "support_message": "",
        "show_help_contacts": False,
        "allow_continue": True,
        "allow_edit": False,
    }


def build_hate_response(analysis):
    """Resposta de moderação para o eixo de discurso de ódio."""
    labels = analysis.get("hate_category_labels") or []
    kinds = (" (" + ", ".join(labels) + ")") if labels else ""

    if analysis.get("block_publication"):
        return {
            "level": "HATE_BLOCK",
            "title": "Isso viola as diretrizes da comunidade",
            "message": (
                "Encontramos discurso de ódio / discriminação" + kinds + ". "
                "O EntreLinhas não permite racismo, homofobia, transfobia, "
                "capacitismo, misoginia, xenofobia, intolerância religiosa nem "
                "nenhum outro ataque a grupos de pessoas. Aqui é pra colocar a sua "
                "dor em palavras, não pra ferir ninguém."
            ),
            "support_message": "",
            "show_help_contacts": False,
            "allow_continue": False,
            "allow_edit": True,
            "block_reason": "Edite o texto removendo a ofensa para poder publicar.",
        }

    return {
        "level": "HATE_WARN",
        "title": "Um cuidado com as palavras",
        "message": (
            "Esse texto tem uma expressão que pode machucar outras pessoas. "
            "Se for um desabafo sobre algo que fizeram com você, tudo bem seguir. "
            "Se for sobre alguém, vale rever antes de publicar."
        ),
        "support_message": "",
        "show_help_contacts": False,
        "allow_continue": True,
        "allow_edit": True,
        "block_reason": "",
    }


def build_content_response(analysis):
    """Escolhe a resposta certa (ódio tem prioridade sobre risco emocional)."""
    if analysis.get("is_hate_speech"):
        return build_hate_response(analysis)
    return build_sensitive_response(
        analysis.get("risk_level", RISK_LOW),
        should_block=analysis.get("should_block", False),
    )


def resolve_content_gate(analysis):
    """Define o portão de publicação consumido pelo front-end e pelas rotas.

    - ``block``: ataque de ódio — não pode publicar.
    - ``ack``: risco emocional ou xingamento isolado — exige confirmação.
    - ``none``: segue direto.
    """
    if analysis.get("block_publication"):
        return "block"
    if analysis.get("risk_level") in (RISK_MEDIUM, RISK_HIGH):
        return "ack"
    if analysis.get("hate_action") == "warn":
        return "ack"
    return "none"
