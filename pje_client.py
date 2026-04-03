"""
Cliente autenticado do PJe por tribunal.
Suporta autenticacao via:
  - Certificado digital A1 (PFX/P12) — mTLS
  - Usuario e senha (fallback)
"""

import re
import requests

TIMEOUT = 30

AUTH_CERT_PATHS = [
    "/pje/seam/resource/rest/usuario/autenticarComCertificado",
    "/pje/seam/resource/rest/autenticacao/certificado",
    "/pje/api/autenticacao/certificado",
]
AUTH_SENHA_PATHS = [
    "/pje/seam/resource/rest/usuario/autenticar",
    "/seam/resource/rest/usuario/autenticar",
]
PROCESS_PATHS = [
    "/pje/seam/resource/rest/processo/consultarByNumero/{numero}",
    "/seam/resource/rest/processo/consultarByNumero/{numero}",
]
DOCS_PATHS = [
    "/pje/seam/resource/rest/processo/{id}/documentos",
    "/seam/resource/rest/processo/{id}/documentos",
]


class PjeClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.token = None
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        # Aceita certificados do servidor mesmo com CA intermediaria
        self.session.verify = True

    # ── Autenticacao ──────────────────────────────────────────────────────────

    def autenticar_com_certificado(self, cert_tuple: tuple) -> bool:
        """
        Autentica via mTLS (certificado A1).
        cert_tuple = (caminho_cert_pem, caminho_chave_pem)
        """
        # Configura o certificado do cliente na sessao
        self.session.cert = cert_tuple

        # Tenta endpoint especifico de certificado primeiro
        for path in AUTH_CERT_PATHS:
            url = f"{self.base_url}{path}"
            try:
                r = self.session.post(url, json={}, timeout=TIMEOUT)
                if r.ok:
                    token = self._extrair_token(r)
                    if token:
                        self._aplicar_token(token)
                        return True
            except requests.RequestException:
                continue

        # Fallback: alguns tribunais aceitam GET com certificado para obter token
        for path in AUTH_CERT_PATHS:
            url = f"{self.base_url}{path}"
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                if r.ok:
                    token = self._extrair_token(r)
                    if token:
                        self._aplicar_token(token)
                        return True
            except requests.RequestException:
                continue

        # Se nenhum endpoint retornou token, mas o cert foi aceito (sessao valida),
        # considera autenticado via cookie de sessao
        try:
            test_url = f"{self.base_url}/pje/seam/resource/rest/processo/consultarByNumero/00000000000000000000"
            r = self.session.get(test_url, timeout=TIMEOUT)
            # 404 = endpoint existe e autenticacao funcionou; 401/403 = falhou
            if r.status_code in (200, 404, 400):
                return True
        except Exception:
            pass

        return False

    def autenticar_com_senha(self, usuario: str, senha: str) -> bool:
        """
        Autentica via usuario e senha.
        Tenta REST JSON primeiro, depois form POST (Seam/JSF).
        """
        # 1. Tenta endpoints REST JSON
        payload_json = {"username": usuario, "password": senha, "token": ""}
        for path in AUTH_SENHA_PATHS:
            url = f"{self.base_url}{path}"
            try:
                r = self.session.post(
                    url, json=payload_json,
                    headers={**self.session.headers, "Content-Type": "application/json"},
                    timeout=TIMEOUT,
                )
                if r.ok:
                    token = self._extrair_token(r)
                    if token:
                        self._aplicar_token(token)
                        return True
            except requests.RequestException:
                continue

        # 2. Fallback: login via formulario web (Seam/JSF)
        form_paths = [
            "/pje/login.seam",
            "/pje/loginForm.seam",
            "/login.seam",
        ]
        for path in form_paths:
            url = f"{self.base_url}{path}"
            try:
                # Busca o formulario para obter viewstate/tokens CSRF
                get_r = self.session.get(url, timeout=TIMEOUT)
                if not get_r.ok:
                    continue

                # Extrai campos ocultos do formulario
                import re
                html = get_r.text
                viewstate = re.search(r'name="javax\.faces\.ViewState"[^>]*value="([^"]+)"', html)
                form_id  = re.search(r'<form[^>]*id="([^"]*login[^"]*)"', html, re.I)

                payload_form = {
                    "javax.faces.ViewState": viewstate.group(1) if viewstate else "",
                    "username": usuario,
                    "password": senha,
                    "j_username": usuario,
                    "j_password": senha,
                }
                if form_id:
                    fid = form_id.group(1)
                    payload_form[f"{fid}:username"] = usuario
                    payload_form[f"{fid}:password"] = senha
                    payload_form[f"{fid}:entrar"] = "Entrar"

                post_r = self.session.post(
                    url, data=payload_form,
                    headers={**self.session.headers, "Content-Type": "application/x-www-form-urlencoded"},
                    timeout=TIMEOUT, allow_redirects=True,
                )

                # Considera autenticado se:
                # - Redireciona para pagina diferente do login
                # - Ou retorna 200 sem "Senha incorreta"/"Login invalido"
                final_url = post_r.url
                body = post_r.text.lower()
                login_failed = any(x in body for x in [
                    "senha incorreta", "login inv", "usuario inv",
                    "credencial inv", "acesso negado", "incorrect", "invalid"
                ])
                if not login_failed and ("login" not in final_url.lower() or post_r.status_code == 200):
                    # Verifica se sessao e valida tentando acessar area restrita
                    test = self.session.get(
                        f"{self.base_url}/pje/ConsultaProcessual/listView.seam",
                        timeout=TIMEOUT, allow_redirects=False
                    )
                    if test.status_code in (200, 302) and "login" not in test.headers.get("Location", "").lower():
                        return True
            except requests.RequestException:
                continue

        return False

    def _extrair_token(self, response: requests.Response) -> str | None:
        try:
            data = response.json()
            return (
                data.get("token")
                or data.get("access_token")
                or data.get("accessToken")
                or data.get("jwtToken")
            )
        except Exception:
            return None

    def _aplicar_token(self, token: str):
        self.token = token
        self.session.headers["Authorization"] = f"Bearer {token}"

    # ── Consultas ─────────────────────────────────────────────────────────────

    def _get(self, path: str) -> dict | None:
        url = f"{self.base_url}{path}"
        try:
            r = self.session.get(url, timeout=TIMEOUT)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def buscar_processo(self, numero: str) -> dict | None:
        numero_limpo = re.sub(r"\D", "", numero)
        for template in PROCESS_PATHS:
            result = self._get(template.format(numero=numero_limpo))
            if result:
                return result
        return None

    def listar_documentos(self, processo_id: str) -> list:
        for template in DOCS_PATHS:
            result = self._get(template.format(id=processo_id))
            if result:
                docs = result if isinstance(result, list) else result.get("documentos", [])
                return [
                    {
                        "id":      d.get("id") or d.get("idDocumento"),
                        "tipo":    d.get("tipoDocumento", {}).get("descricao", "") if isinstance(d.get("tipoDocumento"), dict) else d.get("tipoDocumento", ""),
                        "nome":    d.get("nomeArquivo") or d.get("descricao", ""),
                        "data":    d.get("dataHora") or d.get("data", ""),
                        "autor":   d.get("nomeAutor") or d.get("autor", ""),
                        "url_pdf": self._url_pdf(d),
                    }
                    for d in docs
                ]
        return []

    def _url_pdf(self, doc: dict) -> str:
        doc_id = doc.get("id") or doc.get("idDocumento", "")
        if not doc_id:
            return ""
        return f"{self.base_url}/pje/Processo/ConsultaDocumento/listView.seam?idDocumento={doc_id}"

    def baixar_documento(self, doc_id: str) -> bytes | None:
        url = self._url_pdf({"id": doc_id})
        try:
            r = self.session.get(url, timeout=60)
            if r.ok and "pdf" in r.headers.get("Content-Type", ""):
                return r.content
        except Exception:
            pass
        return None
