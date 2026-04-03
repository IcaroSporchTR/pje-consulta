"""
Cliente da API Publica DataJud (CNJ).

Documentacao: https://datajud-wiki.cnj.jus.br/
Registro de chave: https://www.cnj.jus.br/sistemas/datajud/

Autenticacao: header  Authorization: ApiKey {chave}
Base URL: https://api-publica.datajud.cnj.jus.br/
Indice por tribunal: api_publica_{sigla_lower}  (ex: api_publica_tjsp)
"""

import requests
from datetime import datetime

DATAJUD_BASE = "https://api-publica.datajud.cnj.jus.br"
TIMEOUT = 30


def _headers(api_key: str) -> dict:
    return {
        "Authorization": f"ApiKey {api_key}",
        "Content-Type": "application/json",
    }


def _normalizar_numero(numero: str) -> str:
    """Remove formatacao e retorna apenas digitos."""
    import re
    return re.sub(r"\D", "", numero)


# ── Busca por numero de processo ──────────────────────────────────────────────

def buscar_processo(numero: str, indice: str, api_key: str) -> dict | None:
    """
    Busca um processo pelo numero no DataJud.
    Retorna o documento completo ou None se nao encontrado.
    """
    numero_limpo = _normalizar_numero(numero)
    url = f"{DATAJUD_BASE}/{indice}/_search"
    body = {
        "query": {
            "match": {"numeroProcesso": numero_limpo}
        },
        "size": 1
    }
    r = requests.post(url, headers=_headers(api_key), json=body, timeout=TIMEOUT)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    if not hits:
        return None
    return hits[0].get("_source", {})


def buscar_em_todos_tribunais(numero: str, indices: list, api_key: str) -> list:
    """
    Busca um numero de processo em varios tribunais ao mesmo tempo.
    Retorna lista de (sigla, resultado).
    """
    import concurrent.futures
    results = []

    def _buscar(item):
        sigla, indice = item
        try:
            doc = buscar_processo(numero, indice, api_key)
            if doc:
                return (sigla, doc)
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_buscar, item): item for item in indices}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    return results


# ── Extratores de dados do documento ─────────────────────────────────────────

def extrair_dados_basicos(doc: dict) -> dict:
    return {
        "numero":           doc.get("numeroProcesso", ""),
        "classe":           doc.get("classe", {}).get("nome", ""),
        "classe_codigo":    doc.get("classe", {}).get("codigo", ""),
        "assuntos":         [a.get("nome", "") for a in doc.get("assuntos", [])],
        "assuntos_codigos": [str(a.get("codigo", "")) for a in doc.get("assuntos", [])],
        "orgao":            doc.get("orgaoJulgador", {}).get("nome", ""),
        "orgao_codigo":     doc.get("orgaoJulgador", {}).get("codigo", ""),
        "orgao_municipio":  doc.get("orgaoJulgador", {}).get("municipio", ""),
        "orgao_uf":         doc.get("orgaoJulgador", {}).get("uf", ""),
        "sistema":          doc.get("sistema", {}).get("nome", ""),
        "formato":          doc.get("formato", {}).get("nome", ""),
        "tribunal":         doc.get("tribunal", ""),
        "grau":             doc.get("grau", ""),
        "nivel_sigilo":     doc.get("nivelSigilo", 0),
        "valor_causa":      doc.get("valorCausa", ""),
        "prioridade":       doc.get("prioridade", ""),
        "data_ajuiz":       _formatar_data(doc.get("dataAjuizamento", "")),
        "ultima_atualiz":   _formatar_data(doc.get("dataHoraUltimaAtualizacao", "")),
        "ultima_atualiz_raw": doc.get("dataHoraUltimaAtualizacao", ""),
    }


def extrair_documentos(doc: dict) -> list:
    """
    Extrai documentos/pecas do processo retornados pelo DataJud.
    Nem todos os tribunais enviam documentos via DataJud — depende da configuracao.
    """
    documentos = []
    for d in doc.get("documentos", []):
        documentos.append({
            "id":           d.get("id") or d.get("idDocumento", ""),
            "tipo":         d.get("tipo", {}).get("nome", "") if isinstance(d.get("tipo"), dict) else d.get("tipo", ""),
            "tipo_codigo":  d.get("tipo", {}).get("codigo", "") if isinstance(d.get("tipo"), dict) else "",
            "titulo":       d.get("titulo") or d.get("nome") or d.get("descricao", ""),
            "data":         _formatar_data(d.get("dataHora") or d.get("data", "")),
            "autor":        d.get("autor") or d.get("nomeAutor", ""),
            "polo":         d.get("polo", ""),
            "hash":         d.get("hash", ""),
            "paginas":      d.get("numeroPaginas") or d.get("paginas", ""),
            "sigilo":       d.get("nivelSigilo", 0),
            "vinculados":   [
                {
                    "id":    v.get("id", ""),
                    "tipo":  v.get("tipo", {}).get("nome", "") if isinstance(v.get("tipo"), dict) else v.get("tipo", ""),
                    "titulo": v.get("titulo") or v.get("nome", ""),
                }
                for v in d.get("documentosVinculados", [])
            ],
        })
    return documentos


def extrair_partes(doc: dict) -> list:
    partes = []
    for p in doc.get("partes", []):
        partes.append({
            "polo":     p.get("polo", ""),
            "nome":     p.get("nome", ""),
            "documento": p.get("documento", ""),
            "advogados": [
                {
                    "nome": a.get("nome", ""),
                    "oab":  a.get("numeroDocumentoPrincipal", ""),
                }
                for a in p.get("advogados", [])
            ],
        })
    return partes


def extrair_movimentos(doc: dict) -> list:
    movimentos = []
    for m in doc.get("movimentos", []):
        movimentos.append({
            "data":        _formatar_data(m.get("dataHora", "")),
            "codigo":      m.get("codigo", ""),
            "nome":        m.get("nome", ""),
            "complemento": _extrair_complemento(m),
        })
    # Ordena do mais recente para o mais antigo
    movimentos.sort(key=lambda x: x["data"], reverse=True)
    return movimentos


def _extrair_complemento(movimento: dict) -> str:
    complementos = movimento.get("complementosTabelados", [])
    if complementos:
        return "; ".join(
            c.get("descricao", "") or c.get("nome", "")
            for c in complementos
            if c.get("descricao") or c.get("nome")
        )
    return ""


def _formatar_data(iso: str) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return iso
