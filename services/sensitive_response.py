from utils.sensitive_content import RISK_LOW, RISK_MEDIUM, RISK_HIGH


def build_sensitive_response(risk_level, should_block=False):
    if risk_level == RISK_MEDIUM:
        return {
            "level": RISK_MEDIUM,
            "title": "Um cuidado antes de publicar",
            "message": "Percebemos que seu texto pode refletir um momento difícil. Você não precisa passar por isso sozinho.",
            "show_help_contacts": False,
            "allow_continue": True,
            "allow_edit": True,
        }

    if risk_level == RISK_HIGH:
        return {
            "level": RISK_HIGH,
            "title": "Você importa",
            "message": "Seu texto indica que você pode estar passando por um momento muito difícil. Sua vida importa.",
            "show_help_contacts": True,
            "allow_continue": not should_block,
            "allow_edit": True,
            "block_reason": "Detectamos sinais de risco imediato. Recomendamos fortemente buscar ajuda agora.",
        }

    return {
        "level": RISK_LOW,
        "title": "",
        "message": "",
        "show_help_contacts": False,
        "allow_continue": True,
        "allow_edit": False,
    }