from utils.sensitive_content import RISK_LOW, RISK_MEDIUM, RISK_HIGH


def build_sensitive_response(risk_level, should_block=False):
    if risk_level == RISK_MEDIUM:
        return {
            "level": RISK_MEDIUM,
            "title": "Um cuidado antes de publicar",
            "message": "Percebemos que esse desabafo pode carregar uma dor muito pesada. Voce pode continuar escrevendo, mas queremos lembrar que existe ajuda real disponivel.",
            "show_help_contacts": True,
            "allow_continue": True,
            "allow_edit": True,
        }

    if risk_level == RISK_HIGH:
        return {
            "level": RISK_HIGH,
            "title": "Voce nao precisa atravessar isso sozinho",
            "message": "Seu texto parece tocar uma dor urgente. O EntreLinhas pode te escutar, mas ajuda real tambem pode chegar agora.",
            "show_help_contacts": True,
            "allow_continue": True,
            "allow_edit": True,
            "block_reason": "",
        }

    return {
        "level": RISK_LOW,
        "title": "",
        "message": "",
        "show_help_contacts": False,
        "allow_continue": True,
        "allow_edit": False,
    }
