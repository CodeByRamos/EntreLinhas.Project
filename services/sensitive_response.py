from utils.sensitive_content import RISK_LOW, RISK_MEDIUM, RISK_HIGH


def build_sensitive_response(risk_level, should_block=False):
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
