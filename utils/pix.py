"""Gera o código Pix "copia e cola" (BR Code / padrão EMV do Banco Central).

Sem dependências externas. Produz um Pix ESTÁTICO sem valor fixo (apoio do
quanto a pessoa quiser), a partir da chave + nome + cidade do recebedor.
A chave sozinha já permite Pix manual; o BR Code permite colar no app do banco.
"""

import re
import unicodedata


def _emv(tag: str, value: str) -> str:
    """Campo TLV do EMV: id (2) + tamanho (2) + valor."""
    return f"{tag}{len(value):02d}{value}"


def _ascii_upper(text: str, limit: int) -> str:
    """Nome/cidade do Pix: sem acento, maiúsculo, só A-Z 0-9 e espaço."""
    base = unicodedata.normalize("NFKD", text or "")
    base = "".join(c for c in base if not unicodedata.combining(c))
    base = re.sub(r"[^A-Za-z0-9 ]", " ", base).upper()
    return re.sub(r"\s+", " ", base).strip()[:limit] or "N"


def _crc16(payload: str) -> str:
    """CRC16-CCITT (poly 0x1021, init 0xFFFF) — exigido no campo 63 do BR Code."""
    crc = 0xFFFF
    for byte in payload.encode("utf-8"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def build_pix_brcode(key: str, receiver_name: str = "", city: str = "",
                     description: str = "", amount: float | None = None) -> str:
    """Monta o Pix copia-e-cola. Vazio se a chave não estiver configurada."""
    key = (key or "").strip()
    if not key:
        return ""

    account = _emv("00", "br.gov.bcb.pix") + _emv("01", key)
    if description:
        account += _emv("02", _ascii_upper(description, 40))
    merchant_account = _emv("26", account)

    payload = (
        _emv("00", "01")            # Payload Format Indicator
        + merchant_account          # 26 — conta Pix
        + _emv("52", "0000")        # MCC
        + _emv("53", "986")         # moeda = BRL
        + (_emv("54", f"{amount:.2f}") if amount and amount > 0 else "")
        + _emv("58", "BR")          # país
        + _emv("59", _ascii_upper(receiver_name or "EntreLinhas", 25))
        + _emv("60", _ascii_upper(city or "BRASIL", 15))
        + _emv("62", _emv("05", "***"))  # txid estático
    )
    payload += "6304"               # campo do CRC + tamanho fixo
    return payload + _crc16(payload)
