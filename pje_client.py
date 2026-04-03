"""
Cliente autenticado do PJe por tribunal.
Suporta autenticacao via:
  - Certificado digital A1 (PFX/P12) — mTLS
  - Usuario e senha (fallback)
"""

import re
import requests

TIMEOUT = 30

# Log de tentativas para exibir no frontend
_last_auth_log = []


def get_auth_log() -> list:
    return list(_last_auth_log)


def _log(msg: str):
    _last_auth_log.append(msg)


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
    "/pje/api/v1/processo/{numero}",
    "/pje/api/processo/{numero}",
    "/seam/resource/rest/processo/consultarByNumero/{numero}",
    "/pje/seam/resource/rest/consultaPublica/processo/{numero}",
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

    def _autenticar_keycloak_com_otp(self, otp: str) -> bool:
        """
        Etapa 2: envia o OTP para o Keycloak usando a sessao salva da etapa 1.
        Requer que _keycloak_otp_action esteja definido na instancia.
        """
        action = getattr(self, "_keycloak_otp_action", None)
        if not action:
            _log("  ✗ Sem sessao Keycloak pendente para OTP")
            return False
        try:
            _log(f"[OTP] POST {action[:80]}")
            r = self.session.post(
                action,
                data={"otp": otp, "selectedCredentialId": ""},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=TIMEOUT, allow_redirects=True
            )
            _log(f"  → HTTP {r.status_code} | URL final: {r.url[:100]}")
            body = r.text.lower()
            if any(x in body for x in ["otp inv", "codigo inv", "invalid", "incorrect", "expirou", "expired"]):
                _log("  ✗ OTP invalido ou expirado")
                return False
            # Verifica se voltou ao PJe (autenticado)
            if "pje." in r.url and "sso.cloud" not in r.url:
                _log("  ✓ OTP aceito — redirecionado ao PJe")
                return True
            # Tenta acessar area restrita para confirmar sessao
            test = self.session.get(
                f"{self.base_url}/pje/ConsultaProcessual/listView.seam",
                timeout=TIMEOUT, allow_redirects=False
            )
            if test.status_code in (200, 302) and "login" not in test.headers.get("Location","").lower():
                _log("  ✓ Sessao valida apos OTP")
                return True
            _log(f"  ✗ Sessao invalida apos OTP: {test.status_code}")
        except Exception as e:
            _log(f"  ✗ Erro ao enviar OTP: {e}")
        return False

    def _autenticar_keycloak(self, usuario: str, senha: str, redirect_url: str) -> bool:
        """
        Autentica via Keycloak SSO (sso.cloud.pje.jus.br).
        Extrai realm e client_id da URL de redirect capturada no login.
        Tenta Resource Owner Password Credentials (ROPC) grant.
        """
        import re
        # Extrai parametros do redirect: realm e client_id
        realm_match     = re.search(r'/realms/([^/]+)/', redirect_url)
        client_match    = re.search(r'client_id=([^&]+)', redirect_url)
        redirect_match  = re.search(r'redirect_uri=([^&]+)', redirect_url)

        if not realm_match or not client_match:
            _log(f"  ✗ Nao foi possivel extrair realm/client_id da URL SSO")
            return False

        realm       = realm_match.group(1)
        client_id   = requests.utils.unquote(client_match.group(1))
        redirect_uri = requests.utils.unquote(redirect_match.group(1)) if redirect_match else ""

        token_url = f"https://sso.cloud.pje.jus.br/auth/realms/{realm}/protocol/openid-connect/token"
        _log(f"  [SSO/Keycloak] realm={realm} | client_id={client_id}")
        _log(f"  Token URL: {token_url}")

        # Tenta ROPC (Resource Owner Password Credentials)
        payload = {
            "grant_type": "password",
            "client_id":  client_id,
            "username":   usuario,
            "password":   senha,
            "scope":      "openid",
        }
        try:
            r = requests.post(token_url, data=payload, timeout=TIMEOUT)
            _log(f"  → Keycloak ROPC HTTP {r.status_code}")
            _log(f"  → Resposta: {r.text[:300]}")

            if r.ok:
                data = r.json()
                token = data.get("access_token")
                if token:
                    self._aplicar_token(token)
                    _log("  ✓ Token Keycloak obtido com sucesso via ROPC")
                    return True
                _log("  ✗ Resposta OK mas sem access_token")
            else:
                err = r.json() if "application/json" in r.headers.get("Content-Type","") else {}
                erro_msg = err.get("error_description") or err.get("error") or r.text[:200]
                _log(f"  ✗ Keycloak recusou: {erro_msg}")
                if "invalid_grant" in r.text:
                    _log("  ✗ Credenciais invalidas (usuario ou senha errados)")
                if "otp" in r.text.lower() or "totp" in r.text.lower():
                    _log("  ⚠ KEYCLOAK EXIGE OTP/2FA — necessario segundo fator")
        except Exception as e:
            _log(f"  ✗ Erro ao contactar Keycloak: {e}")

        # Fallback: tenta o fluxo Authorization Code via POST direto no Keycloak
        try:
            auth_url = f"https://sso.cloud.pje.jus.br/auth/realms/{realm}/protocol/openid-connect/auth"
            _log(f"  [SSO] Tentando Authorization Code flow em {auth_url}")
            # Busca pagina de login do Keycloak
            get_r = self.session.get(
                f"{auth_url}?response_type=code&client_id={client_id}"
                f"&redirect_uri={requests.utils.quote(redirect_uri)}&scope=openid",
                timeout=TIMEOUT
            )
            _log(f"  → GET login Keycloak: HTTP {get_r.status_code} | URL: {get_r.url[:100]}")
            html = get_r.text
            # Localiza action do formulario de login
            action = re.search(r'action="([^"]+)"', html)
            if action:
                login_action = action.group(1).replace("&amp;", "&")
                _log(f"  → Form action: {login_action[:100]}")
                post_r = self.session.post(
                    login_action,
                    data={"username": usuario, "password": senha, "credentialId": ""},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=TIMEOUT, allow_redirects=True
                )
                _log(f"  → POST Keycloak form: HTTP {post_r.status_code} | URL final: {post_r.url[:100]}")
                body_lower = post_r.text.lower()
                otp_action = re.search(r'action="([^"]+)"', post_r.text)
                if ("otp" in body_lower or "totp" in body_lower or "verification" in body_lower
                        or "segundo fator" in body_lower or "authenticator" in body_lower):
                    _log("  ⚠ SEGUNDO FATOR (OTP) EXIGIDO — aguardando codigo")
                    # Salva action para etapa 2
                    if otp_action:
                        self._keycloak_otp_action = otp_action.group(1).replace("&amp;", "&")
                        _log(f"  OTP action salva: {self._keycloak_otp_action[:80]}")
                    return "otp_required"  # sinal especial para o frontend
                elif "pje.tjmg" in post_r.url or (redirect_uri and redirect_uri.split("/")[2] in post_r.url):
                    _log("  ✓ Redirecionado de volta ao PJe — autenticacao bem sucedida")
                    return True
                else:
                    _log(f"  ✗ Pos-login inesperado: {post_r.text[:300]}")
        except Exception as e:
            _log(f"  ✗ Erro no Authorization Code flow: {e}")

        return False

    def autenticar_com_senha(self, usuario: str, senha: str) -> bool:
        """
        Autentica via usuario e senha.
        Tenta REST JSON primeiro, depois form POST (Seam/JSF).
        Registra log detalhado em _last_auth_log.
        """
        _last_auth_log.clear()
        _log(f"Iniciando autenticacao para usuario: {usuario[:3]}***")
        _log(f"URL base do tribunal: {self.base_url}")

        # 1. Tenta endpoints REST JSON
        payload_json = {"username": usuario, "password": senha, "token": ""}
        for path in AUTH_SENHA_PATHS:
            url = f"{self.base_url}{path}"
            try:
                _log(f"[REST] POST {url}")
                r = self.session.post(
                    url, json=payload_json,
                    headers={**self.session.headers, "Content-Type": "application/json"},
                    timeout=TIMEOUT,
                )
                _log(f"  → HTTP {r.status_code} | Content-Type: {r.headers.get('Content-Type','')[:60]}")
                _log(f"  → Resposta: {r.text[:200]}")
                if r.ok:
                    token = self._extrair_token(r)
                    if token:
                        self._aplicar_token(token)
                        _log("  ✓ Token JWT obtido com sucesso")
                        return True
                    else:
                        _log("  ✗ HTTP OK mas sem token na resposta")
                else:
                    _log(f"  ✗ Falha HTTP {r.status_code}")
            except requests.RequestException as e:
                _log(f"  ✗ Erro de conexao: {e}")

        # 2. Fallback: login via formulario web (Seam/JSF)
        form_paths = [
            "/pje/login.seam",
            "/pje/loginForm.seam",
            "/login.seam",
        ]
        for path in form_paths:
            url = f"{self.base_url}{path}"
            try:
                _log(f"[FORM] GET {url}")
                get_r = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                _log(f"  → HTTP {get_r.status_code} | URL final: {get_r.url}")
                if not get_r.ok:
                    _log(f"  ✗ Nao foi possivel carregar o formulario")
                    continue

                import re
                html = get_r.text
                viewstate = re.search(r'name="javax\.faces\.ViewState"[^>]*value="([^"]+)"', html)
                form_id   = re.search(r'<form[^>]*id="([^"]*login[^"]*)"', html, re.I)
                mfa_hint  = re.search(r'(token|otp|segundo.fator|autenticacao.dupla|two.factor|captcha|recaptcha)', html, re.I)

                # Detecta redirecionamento para Keycloak SSO
                if "sso.cloud.pje.jus.br" in get_r.url:
                    _log(f"  → Detectado Keycloak SSO — usando fluxo OAuth")
                    resultado_kc = self._autenticar_keycloak(usuario, senha, get_r.url)
                    if resultado_kc is True:
                        return True
                    if resultado_kc == "otp_required":
                        return "otp_required"  # propaga sinal para o frontend
                    continue

                _log(f"  ViewState encontrado: {'sim' if viewstate else 'nao'}")
                _log(f"  Form ID: {form_id.group(1) if form_id else 'nao encontrado'}")
                if mfa_hint:
                    _log(f"  ⚠ POSSIVEL MFA/2FA detectado na pagina: '{mfa_hint.group(1)}'")

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
                    payload_form[f"{fid}:entrar"]   = "Entrar"

                _log(f"[FORM] POST {url} com {len(payload_form)} campos")
                post_r = self.session.post(
                    url, data=payload_form,
                    headers={**self.session.headers, "Content-Type": "application/x-www-form-urlencoded"},
                    timeout=TIMEOUT, allow_redirects=True,
                )
                _log(f"  → HTTP {post_r.status_code} | URL final: {post_r.url}")

                body = post_r.text.lower()
                erros_detectados = [x for x in [
                    "senha incorreta", "login inv", "usuario inv", "credencial inv",
                    "acesso negado", "incorrect", "invalid", "autenticacao falhou",
                    "usuario ou senha", "nao autorizado"
                ] if x in body]

                mfa_pos = re.search(r'(token|otp|segundo.fator|two.factor|codigo de verificacao)', body, re.I)
                if mfa_pos:
                    _log(f"  ⚠ PAGINA POS-LOGIN EXIGE 2o FATOR: '{mfa_pos.group(1)}'")
                    _log(f"  Trecho da pagina: {post_r.text[max(0,post_r.text.lower().find(mfa_pos.group(1))-100):post_r.text.lower().find(mfa_pos.group(1))+200]}")

                if erros_detectados:
                    _log(f"  ✗ Mensagem de erro detectada: {erros_detectados}")
                    _log(f"  Trecho HTML: {post_r.text[:500]}")
                    continue

                test = self.session.get(
                    f"{self.base_url}/pje/ConsultaProcessual/listView.seam",
                    timeout=TIMEOUT, allow_redirects=False
                )
                _log(f"  Teste sessao: HTTP {test.status_code} | Location: {test.headers.get('Location','')[:80]}")
                if test.status_code in (200, 302) and "login" not in test.headers.get("Location", "").lower():
                    _log("  ✓ Sessao autenticada com sucesso via formulario")
                    return True
                else:
                    _log("  ✗ Sessao nao autenticada — redirecionado para login")

            except requests.RequestException as e:
                _log(f"  ✗ Erro de conexao: {e}")

        _log("✗ Todas as tentativas de autenticacao falharam")
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
        """
        Tenta varios endpoints e formatos de numero.
        Retorna o primeiro resultado encontrado ou None.
        """
        _last_auth_log.append("=== Busca de processo ===")
        # Formatos a tentar: so digitos e formato CNJ com pontuacao
        digitos = re.sub(r"\D", "", numero)
        # Reconstroi formato CNJ se o numero tiver 20 digitos
        if len(digitos) == 20:
            cnj = f"{digitos[0:7]}-{digitos[7:9]}.{digitos[9:13]}.{digitos[13]}.{digitos[14:16]}.{digitos[16:20]}"
        else:
            cnj = numero.strip()

        for fmt_label, fmt_numero in [("CNJ", cnj), ("digitos", digitos)]:
            for template in PROCESS_PATHS:
                url_path = template.format(numero=fmt_numero)
                full_url = f"{self.base_url}{url_path}"
                try:
                    r = self.session.get(full_url, timeout=TIMEOUT, allow_redirects=True)
                    _last_auth_log.append(f"  [processo/{fmt_label}] GET {url_path} → {r.status_code}")
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            if data:
                                _last_auth_log.append(f"  ✓ Encontrado via {url_path}")
                                return data
                        except Exception:
                            pass
                    elif r.status_code == 401:
                        _last_auth_log.append("  ⚠ Nao autorizado (sessao pode ter expirado)")
                except requests.RequestException as e:
                    _last_auth_log.append(f"  ✗ Erro: {e}")

        _last_auth_log.append("  ✗ Processo nao encontrado em nenhum endpoint")
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
