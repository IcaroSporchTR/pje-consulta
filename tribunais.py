"""
Mapeamento de tribunais: sigla -> URL PJe + indice DataJud.
Adicione ou ajuste conforme necessidade.
"""

TRIBUNAIS = {
    # Sigla: (nome completo, URL base PJe, indice DataJud)
    "TJSP":  ("Tribunal de Justica de Sao Paulo",       "https://pje.tjsp.jus.br",          "api_publica_tjsp"),
    "TJRJ":  ("Tribunal de Justica do Rio de Janeiro",  "https://pje.tjrj.jus.br",          "api_publica_tjrj"),
    "TJMG":  ("Tribunal de Justica de Minas Gerais",    "https://pje.tjmg.jus.br",          "api_publica_tjmg"),
    "TJRS":  ("Tribunal de Justica do Rio Grande do Sul","https://pje.tjrs.jus.br",          "api_publica_tjrs"),
    "TJPR":  ("Tribunal de Justica do Parana",          "https://projudi.tjpr.jus.br/pje",  "api_publica_tjpr"),
    "TJBA":  ("Tribunal de Justica da Bahia",           "https://pje.tjba.jus.br/pje",      "api_publica_tjba"),
    "TJSC":  ("Tribunal de Justica de Santa Catarina",  "https://pje.tjsc.jus.br",          "api_publica_tjsc"),
    "TJPE":  ("Tribunal de Justica de Pernambuco",      "https://pje.tjpe.jus.br",          "api_publica_tjpe"),
    "TJCE":  ("Tribunal de Justica do Ceara",           "https://pje.tjce.jus.br",          "api_publica_tjce"),
    "TJGO":  ("Tribunal de Justica de Goias",           "https://pje.tjgo.jus.br",          "api_publica_tjgo"),
    "TJDF":  ("Tribunal de Justica do DF e Territorios","https://pje.tjdft.jus.br",         "api_publica_tjdft"),
    "TJMT":  ("Tribunal de Justica do Mato Grosso",     "https://pje.tjmt.jus.br",          "api_publica_tjmt"),
    "TJMS":  ("Tribunal de Justica do Mato Grosso do Sul","https://pje.tjms.jus.br",        "api_publica_tjms"),
    "TJPA":  ("Tribunal de Justica do Para",            "https://pje.tjpa.jus.br",          "api_publica_tjpa"),
    "TJAM":  ("Tribunal de Justica do Amazonas",        "https://pje.tjam.jus.br",          "api_publica_tjam"),
    "TJAL":  ("Tribunal de Justica de Alagoas",         "https://pje.tjal.jus.br",          "api_publica_tjal"),
    "TJES":  ("Tribunal de Justica do Espirito Santo",  "https://pje.tjes.jus.br",          "api_publica_tjes"),
    "TJPB":  ("Tribunal de Justica da Paraiba",         "https://pje.tjpb.jus.br",          "api_publica_tjpb"),
    "TJPI":  ("Tribunal de Justica do Piaui",           "https://pje.tjpi.jus.br",          "api_publica_tjpi"),
    "TJMA":  ("Tribunal de Justica do Maranhao",        "https://pje.tjma.jus.br",          "api_publica_tjma"),
    "TJRN":  ("Tribunal de Justica do Rio Grande do Norte","https://pje.tjrn.jus.br",       "api_publica_tjrn"),
    "TJSE":  ("Tribunal de Justica de Sergipe",         "https://pje.tjse.jus.br",          "api_publica_tjse"),
    "TJRO":  ("Tribunal de Justica de Rondonia",        "https://pje.tjro.jus.br",          "api_publica_tjro"),
    "TJTO":  ("Tribunal de Justica do Tocantins",       "https://pje.tjto.jus.br",          "api_publica_tjto"),
    "TJAC":  ("Tribunal de Justica do Acre",            "https://pje.tjac.jus.br",          "api_publica_tjac"),
    "TJAP":  ("Tribunal de Justica do Amapa",           "https://pje.tjap.jus.br",          "api_publica_tjap"),
    "TJRR":  ("Tribunal de Justica de Roraima",         "https://pje.tjrr.jus.br",          "api_publica_tjrr"),
    # Trabalhistas
    "TRT1":  ("TRT 1a Regiao (RJ)",                     "https://pje.trt1.jus.br/primeirograu", "api_publica_trt1"),
    "TRT2":  ("TRT 2a Regiao (SP Grande)",              "https://pje.trt2.jus.br/primeirograu", "api_publica_trt2"),
    "TRT3":  ("TRT 3a Regiao (MG)",                     "https://pje.trt3.jus.br/primeirograu", "api_publica_trt3"),
    "TRT4":  ("TRT 4a Regiao (RS)",                     "https://pje.trt4.jus.br/primeirograu", "api_publica_trt4"),
    "TRT5":  ("TRT 5a Regiao (BA)",                     "https://pje.trt5.jus.br/primeirograu", "api_publica_trt5"),
    "TRT15": ("TRT 15a Regiao (SP Interior)",           "https://pje.trt15.jus.br/primeirograu","api_publica_trt15"),
    # Federais
    "TRF1":  ("Tribunal Regional Federal 1a Regiao",    "https://pje1g.trf1.jus.br/pje",    "api_publica_trf1"),
    "TRF2":  ("Tribunal Regional Federal 2a Regiao",    "https://pje.trf2.jus.br/pje",      "api_publica_trf2"),
    "TRF3":  ("Tribunal Regional Federal 3a Regiao",    "https://pje1g.trf3.jus.br/pje",    "api_publica_trf3"),
    "TRF4":  ("Tribunal Regional Federal 4a Regiao",    "https://pje.trf4.jus.br/pje",      "api_publica_trf4"),
    "TRF5":  ("Tribunal Regional Federal 5a Regiao",    "https://pje.trf5.jus.br/pje",      "api_publica_trf5"),
    # Superiores
    "STJ":   ("Superior Tribunal de Justica",           "https://pje.stj.jus.br/pje",       "api_publica_stj"),
    "TST":   ("Tribunal Superior do Trabalho",          "https://pje.tst.jus.br/tst",       "api_publica_tst"),
    "STF":   ("Supremo Tribunal Federal",               "https://portal.stf.jus.br",        "api_publica_stf"),
}


def get_by_sigla(sigla: str):
    return TRIBUNAIS.get(sigla.upper())


def sigla_options():
    return [(sig, f"{sig} — {v[0]}") for sig, v in TRIBUNAIS.items()]


def detect_tribunal_from_numero(numero: str) -> str | None:
    """
    Tenta identificar o tribunal pelo codigo CNJ no numero do processo.
    Formato: NNNNNNN-DD.AAAA.J.TT.OOOO
    J=justica: 1=federal 2=estadual 5=trabalhista
    TT=codigo tribunal
    """
    import re
    m = re.match(r"\d{7}-\d{2}\.\d{4}\.(\d)\.(\d{2})\.\d{4}", numero.strip())
    if not m:
        return None
    j, tt = m.group(1), m.group(2)
    tt_int = int(tt)

    if j == "5":  # trabalhista
        if tt_int <= 24:
            return f"TRT{tt_int}"
    elif j == "4":  # federal
        mapa_trf = {"01": "TRF1", "02": "TRF2", "03": "TRF3", "04": "TRF4", "05": "TRF5"}
        return mapa_trf.get(tt)
    elif j == "2":  # estadual
        mapa_tj = {
            "26": "TJSP", "19": "TJRJ", "13": "TJMG", "21": "TJRS", "16": "TJPR",
            "05": "TJBA", "12": "TJSC", "17": "TJPE", "06": "TJCE", "09": "TJGO",
            "07": "TJDF", "11": "TJMT", "15": "TJMS", "14": "TJPA", "04": "TJAM",
            "02": "TJAL", "08": "TJES", "15": "TJPB", "18": "TJPI", "10": "TJMA",
            "20": "TJRN", "25": "TJSE", "22": "TJRO", "27": "TJTO", "01": "TJAC",
            "03": "TJAP", "23": "TJRR",
        }
        return mapa_tj.get(tt)
    return None
