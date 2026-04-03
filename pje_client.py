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
    # PJe 2.x — query param
    "/pje/api/v1/processo/consultarProcesso?numero={numero}",
    "/pje/api/v1/processo?numero={numero}",
    "/pje/api/v1/consultaProcessual/processo?numero={numero}",
    # PJe 2.x — path param
    "/pje/api/v1/processo/{numero}",
    "/pje/api/v1/processo/consultarByNumero/{numero}",
    # PJe 1.x legacy
    "/pje/seam/resource/rest/processo/consultarByNumero/{numero}",
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
            _log(f"  → HTTP {r.status_code} | URL: {r.url[:100]}")
            body = r.text.lower()

            # OTP invalido
            if any(x in body for x in ["otp inv", "codigo inv", "invalid", "incorrect", "expirou", "expired"]):
                _log("  ✗ OTP invalido ou expirado")
                return False

            # Keycloak redirecionou para o PJe
            pje_host = self.base_url.split("//")[-1].split("/")[0]
            if pje_host in r.url and "sso.cloud" not in r.url:
                if r.status_code == 200:
                    _log(f"  ✓ Sessao PJe ativa — {r.url[:80]}")
                    return True
                # Para status nao-200 no callback, tenta paginas conhecidas do PJe
                _log(f"  → HTTP {r.status_code} no callback — verificando sessao")
                for check_path in ["/pje/Painel/Painel/listView.seam", "/pje/painel/", "/pje/"]:
                    try:
                        test = self.session.get(f"{self.base_url}{check_path}",
                                                timeout=TIMEOUT, allow_redirects=False)
                        loc = test.headers.get("Location", "")
                        _log(f"  → {check_path}: HTTP {test.status_code} | Loc: {loc[:60]}")
                        if test.status_code == 200:
                            _log("  ✓ Sessao ativa")
                            return True
                        if test.status_code == 302 and "login" not in loc.lower() and "sso.cloud" not in loc:
                            _log("  ✓ Redirect interno — sessao ativa")
                            return True
                    except Exception:
                        pass
                _log("  ✗ Sessao invalida")
                return False

            _log(f"  ✗ URL inesperada apos OTP: {r.url[:100]}")
        except Exception as e:
            _log(f"  ✗ Erro ao enviar OTP: {e}")
        return False

    def _autenticar_keycloak(self, usuario: str, senha: str, redirect_url: str,
                             otp: str = "", login_html: str = "") -> bool:
        """
        Autentica via Keycloak SSO (sso.cloud.pje.jus.br).
        Usa o HTML da pagina de login ja carregada (passado via login_html)
        para preservar o state/nonce que o PJe criou — evita o erro 400.
        """
        realm_match  = re.search(r'/realms/([^/]+)/', redirect_url)
        client_match = re.search(r'client_id=([^&]+)', redirect_url)

        if not realm_match or not client_match:
            _log("  ✗ Nao foi possivel extrair realm/client_id da URL SSO")
            return False

        realm     = realm_match.group(1)
        client_id = requests.utils.unquote(client_match.group(1))
        _log(f"  [SSO/Keycloak] realm={realm} | client_id={client_id}")

        # Tenta ROPC primeiro (mais simples, falha se exigir client_secret)
        token_url = f"https://sso.cloud.pje.jus.br/auth/realms/{realm}/protocol/openid-connect/token"
        try:
            r = requests.post(token_url, data={
                "grant_type": "password", "client_id": client_id,
                "username": usuario, "password": senha, "scope": "openid",
            }, timeout=TIMEOUT)
            _log(f"  → ROPC HTTP {r.status_code}")
            if r.ok:
                token = r.json().get("access_token")
                if token:
                    self._aplicar_token(token)
                    _log("  ✓ Token via ROPC")
                    return True
            else:
                err = r.json() if "application/json" in r.headers.get("Content-Type","") else {}
                _log(f"  ✗ ROPC recusado: {err.get('error_description') or r.text[:120]}")
        except Exception as e:
            _log(f"  ✗ Erro ROPC: {e}")

        # Authorization Code flow — usa o HTML JA carregado para manter o state do PJe
        try:
            if login_html:
                html = login_html
                _log("  → Usando pagina Keycloak ja carregada (state preservado)")
            else:
                redirect_match = re.search(r'redirect_uri=([^&]+)', redirect_url)
                redirect_uri   = requests.utils.unquote(redirect_match.group(1)) if redirect_match else ""
                auth_url = (f"https://sso.cloud.pje.jus.br/auth/realms/{realm}"
                            f"/protocol/openid-connect/auth"
                            f"?response_type=code&client_id={client_id}"
                            f"&redirect_uri={requests.utils.quote(redirect_uri)}&scope=openid")
                gr = self.session.get(auth_url, timeout=TIMEOUT)
                html = gr.text
                _log(f"  → GET Keycloak: HTTP {gr.status_code}")

            action = re.search(r'action="([^"]+)"', html)
            if not action:
                _log("  ✗ Form action nao encontrado na pagina de login")
                return False

            login_action = action.group(1).replace("&amp;", "&")
            _log(f"  → POST credenciais: {login_action[:80]}")
            post_r = self.session.post(
                login_action,
                data={"username": usuario, "password": senha, "credentialId": ""},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=TIMEOUT, allow_redirects=True,
            )
            _log(f"  → HTTP {post_r.status_code} | URL: {post_r.url[:100]}")

            body_lower = post_r.text.lower()
            otp_match  = re.search(r'action="([^"]+)"', post_r.text)
            pje_host   = self.base_url.split("//")[-1].split("/")[0]

            # OTP exigido (ainda no SSO)
            if any(x in body_lower for x in ("otp", "totp", "verification", "segundo fator", "authenticator")):
                _log("  ⚠ SEGUNDO FATOR (OTP) EXIGIDO")
                if otp_match:
                    self._keycloak_otp_action = otp_match.group(1).replace("&amp;", "&")
                if otp and otp_match:
                    _log("  → Submetendo OTP diretamente")
                    return self._autenticar_keycloak_com_otp(otp)
                return "otp_required"

            # Redirecionado de volta ao PJe
            if pje_host in post_r.url and "sso.cloud" not in post_r.url:
                if post_r.status_code == 200:
                    _log(f"  ✓ Sessao PJe ativa — {post_r.url[:80]}")
                    return True
                _log(f"  → HTTP {post_r.status_code} no callback — verificando sessao")
                for check_path in ["/pje/Painel/Painel/listView.seam", "/pje/painel/", "/pje/"]:
                    try:
                        test = self.session.get(f"{self.base_url}{check_path}",
                                                timeout=TIMEOUT, allow_redirects=False)
                        loc = test.headers.get("Location", "")
                        _log(f"  → {check_path}: HTTP {test.status_code} | Loc: {loc[:60]}")
                        if test.status_code == 200:
                            _log("  ✓ Sessao ativa")
                            return True
                        if test.status_code == 302 and "login" not in loc.lower() and "sso.cloud" not in loc:
                            _log("  ✓ Redirect interno — sessao ativa")
                            return True
                    except Exception:
                        pass
                _log("  ✗ Sessao invalida")
                return False

            _log(f"  ✗ Resposta inesperada: URL={post_r.url[:80]} | body={post_r.text[:150]}")
        except Exception as e:
            _log(f"  ✗ Erro no Authorization Code flow: {e}")

        return False

    def autenticar_com_senha(self, usuario: str, senha: str, otp: str = "") -> bool:
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
                    # Passa o HTML ja carregado para preservar o state/nonce do PJe
                    resultado_kc = self._autenticar_keycloak(
                        usuario, senha, get_r.url, otp=otp, login_html=get_r.text
                    )
                    if resultado_kc is True:
                        return True
                    if resultado_kc == "otp_required":
                        return "otp_required"
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
        1. Tenta endpoints REST (PJe 1.x e 2.x)
        2. Fallback: scraping da interface web do PJe
        """
        _last_auth_log.append("=== Busca de processo ===")
        digitos = re.sub(r"\D", "", numero)
        if len(digitos) == 20:
            cnj = f"{digitos[0:7]}-{digitos[7:9]}.{digitos[9:13]}.{digitos[13]}.{digitos[14:16]}.{digitos[16:20]}"
        else:
            cnj = numero.strip()

        # 1. Tenta REST
        for fmt_label, fmt_numero in [("CNJ", cnj), ("digitos", digitos)]:
            for template in PROCESS_PATHS:
                url_path = template.format(numero=fmt_numero)
                try:
                    r = self.session.get(f"{self.base_url}{url_path}", timeout=TIMEOUT, allow_redirects=True)
                    _last_auth_log.append(f"  [{fmt_label}] {url_path[:65]} → {r.status_code}")
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            if data:
                                _last_auth_log.append("  ✓ Encontrado via REST!")
                                return data
                        except Exception:
                            pass
                except requests.RequestException as e:
                    _last_auth_log.append(f"  ✗ {e}")

        # 2. Fallback: scraping web
        _last_auth_log.append("  → REST indisponivel; tentando interface web...")
        return self._buscar_processo_web(cnj, digitos)

    def _obter_urls_consulta_do_menu(self) -> list:
        """
        Navega pelo menu do PJe autenticado e retorna paths de consulta processual.
        Busca ampla: href, onclick, JS, data-* — o menu do TJMG e JavaScript-driven.
        """
        home_url = f"{self.base_url}/pje/QuadroAviso/listViewQuadroAvisoMensagem.seam"
        try:
            r = self.session.get(home_url, timeout=TIMEOUT, allow_redirects=True)
            _last_auth_log.append(f"  [nav] QuadroAviso → {r.status_code} | {len(r.text)} bytes")
            if r.status_code != 200:
                return []

            # Coleta ampla: qualquer trecho que contenha "/pje/" no HTML inteiro
            # (href, onclick, window.location, JSON, data-url, etc.)
            raw_paths = re.findall(r'(/pje/[A-Za-z0-9_./?=&%;:-]{4,})', r.text)
            url_set = list(dict.fromkeys(raw_paths))  # dedup mantendo ordem

            _last_auth_log.append(f"  [nav] {len(url_set)} caminhos /pje/ no HTML")
            for u in url_set[:20]:
                _last_auth_log.append(f"  [nav]   {u}")

            # Linhas do HTML que contenham "Consulta" ou "Processo" (menu textual)
            kw_lines = [
                ln.strip() for ln in r.text.splitlines()
                if re.search(r'[Cc]onsult|[Pp]rocesso', ln) and ln.strip()
                   and len(ln.strip()) < 300
            ]
            _last_auth_log.append(f"  [nav] {len(kw_lines)} linhas HTML com Consulta/Processo:")
            for ln in kw_lines[:12]:
                _last_auth_log.append(f"  [nav]   {ln[:200]}")

            # Snippet inicial do HTML para ver estrutura geral
            _last_auth_log.append(f"  [nav] HTML[0:600]: {r.text[:600]!r}")

            # Filtra candidatos de consulta descartando ruido
            skip = ("login", "logout", "aviso", "painel", "ajax", "resource",
                    ".js", ".css", ".png", ".ico", "conversationId", "javax")
            want = ("consulta", "processo", "pesquis", "autos", "tarefa", "audiencia")
            candidatos = []
            for p in url_set:
                low = p.lower()
                if any(x in low for x in skip):
                    continue
                if any(x in low for x in want):
                    # Normaliza: remove query string para a tentativa GET
                    clean = p.split("?")[0].split(";")[0]
                    if clean not in candidatos:
                        candidatos.append(clean)

            _last_auth_log.append(
                f"  [nav] {len(candidatos)} candidatos de consulta apos filtro"
            )
            return candidatos
        except Exception as e:
            _last_auth_log.append(f"  [nav] Erro ao navegar menu: {e}")
            return []

    def _buscar_processo_web(self, cnj: str, digitos: str) -> dict | None:
        """Busca o processo via interface web do PJe (scraping HTML)."""

        # Descobre os caminhos reais a partir do menu autenticado,
        # depois completa com paths padrao PJe 1.x como fallback.
        paths_do_menu = self._obter_urls_consulta_do_menu()
        paths_fallback = [
            "/pje/Processo/ConsultaProcessual/listView.seam",
            "/pje/ConsultaProcessual/listView.seam",
            "/pje/advogado/processo/pesquisa.seam",
            "/pje/ConsultaProcessual/processoPesquisar.seam",
        ]
        vistos = set()
        consulta_paths = []
        for p in paths_do_menu + paths_fallback:
            if p not in vistos:
                vistos.add(p)
                consulta_paths.append(p)

        for path in consulta_paths:
            try:
                url_get = path if path.startswith("http") else f"{self.base_url}{path}"
                r = self.session.get(url_get, timeout=TIMEOUT, allow_redirects=True)
                _last_auth_log.append(f"  [web] GET {path[:70]} → {r.status_code} ({len(r.text)} bytes) | url={r.url[:80]}")
                if r.status_code != 200 or len(r.text) < 500:
                    continue

                # Diagnostico: primeiros 400 chars do HTML (revela estrutura da pagina)
                _last_auth_log.append(f"  [web] HTML[0:400]: {r.text[:400]!r}")

                # Encontra o form principal (id="fPP" e PJe padrao; se nao, pega o primeiro)
                form_tag_m = (
                    re.search(r'(<form[^>]*id="fPP"[^>]*>)', r.text, re.I | re.DOTALL)
                    or re.search(r'(<form[^>]*>)',           r.text, re.I | re.DOTALL)
                )
                action_url = url_get  # fallback: mesma URL
                if form_tag_m:
                    act_m = re.search(r'action="([^"]+)"', form_tag_m.group(1))
                    if act_m:
                        action_raw = act_m.group(1).replace("&amp;", "&")
                        action_url = action_raw if action_raw.startswith("http") else f"{self.base_url}{action_raw}"

                # Extrai ViewState (suporta name= e id=)
                vs_m = (
                    re.search(r'name="javax\.faces\.ViewState"[^>]*value="([^"]+)"', r.text)
                    or re.search(r'id="javax\.faces\.ViewState"\s+value="([^"]+)"', r.text)
                    or re.search(r'javax\.faces\.ViewState[^>]*value="([^"]+)"', r.text)
                )
                if not vs_m:
                    _last_auth_log.append(f"  [web] ViewState NAO encontrado — pagina nao e JSF/Seam")
                    continue

                # Todos os campos name= da pagina (sem limite — necessario para mapear CNJ)
                all_names = re.findall(r'name="([^"]+)"', r.text)
                _last_auth_log.append(f"  [web] Campos fPP: {[n for n in all_names if 'fPP' in n]}")

                # ── Parseia CNJ em componentes ──────────────────────────────────
                # Formato: NNNNNNN-DD.AAAA.J.TT.OOOO
                cnj_m = re.match(r'(\d{7})-(\d{2})\.(\d{4})\.(\d)\.(\d{2})\.(\d{4})', cnj)
                cnj_partes = {}
                if cnj_m:
                    cnj_partes = {
                        # Chaves = sufixo lowercase do name= JSF (fPP:numeroProcesso:<sufixo>)
                        # Mapeado dos campos REAIS observados no TJMG + aliases genericos
                        "sequencial":                cnj_m.group(1),  # 0329577
                        "numerosequencial":          cnj_m.group(1),  # PJe generrico
                        "digitoverificador":         cnj_m.group(2),  # 75
                        "numerodigitoverificador":   cnj_m.group(2),  # TJMG real
                        "anoinicio":                 cnj_m.group(3),  # 2014
                        "ano":                       cnj_m.group(3),  # TJMG real: fPP:numeroProcesso:Ano
                        "codigojustica":             cnj_m.group(4),  # 8
                        "justica":                   cnj_m.group(4),
                        "ramojustica":               cnj_m.group(4),  # TJMG real: fPP:numeroProcesso:ramoJustica
                        "codigotribunal":            cnj_m.group(5),  # 13
                        "tribunal":                  cnj_m.group(5),
                        "respectivotribunal":        cnj_m.group(5),  # TJMG real: fPP:numeroProcesso:respectivoTribunal
                        "codigoorigem":              cnj_m.group(6),  # 0145
                        "origem":                    cnj_m.group(6),
                        "numeroorgaojustica":        cnj_m.group(6),  # TJMG real: fPP:numeroProcesso:NumeroOrgaoJustica
                    }

                _last_auth_log.append(f"  [web] CNJ partes: {cnj_partes}")
                _last_auth_log.append(f"  [web] Action: {action_url[:70]}")

                form_data = {"javax.faces.ViewState": vs_m.group(1)}

                # Preenche cada subcomponente pelo sufixo do name (PJe 1.x padrao)
                filled_any = False
                for name in all_names:
                    suffix = name.lower().rsplit(":", 1)[-1]  # ultimo segmento do id JSF
                    if suffix in cnj_partes:
                        form_data[name] = cnj_partes[suffix]
                        filled_any = True
                    # aliases menos comuns
                    elif suffix in ("numprocesso", "numero", "numeroprocesso"):
                        form_data[name] = cnj_partes.get("sequencial", cnj)
                        filled_any = True

                # Fallback se nenhum campo foi mapeado
                if not filled_any:
                    if cnj_partes:
                        form_data["fPP:numeroProcesso:numeroSequencial"] = cnj_partes["sequencial"]
                    else:
                        form_data["fPP:numProcesso:numProcesso"] = cnj
                        form_data["numeroProcesso"]              = cnj

                # Botao de pesquisa
                btn_name = next(
                    (n for n in all_names if any(
                        x in n.lower() for x in ("searchprocessos", "pesquisar", "buscar", "search")
                    )), None
                )
                if btn_name:
                    form_data[btn_name] = btn_name

                _last_auth_log.append(f"  [web] form_data: {form_data}")

                post_r = self.session.post(action_url, data=form_data,
                                           timeout=TIMEOUT, allow_redirects=True)
                _last_auth_log.append(
                    f"  [web] POST → {post_r.status_code} | URL: {post_r.url[:100]} ({len(post_r.text)} bytes)"
                )
                # Diagnostico da resposta
                _last_auth_log.append(f"  [web] RESP[0:400]: {post_r.text[:400]!r}")

                if post_r.status_code not in (200, 302):
                    continue

                # Verifica se o ID do processo esta na URL apos redirect
                url_id_m = re.search(r'[?&]idProcesso=(\d+)', post_r.url)
                if url_id_m:
                    pid = url_id_m.group(1)
                    _last_auth_log.append(f"  ✓ ID do processo na URL apos redirect: {pid}")
                    return {"id": pid, "idProcesso": pid, "numero": cnj,
                            "_fonte": "web", "_url": post_r.url}

                # Procura links com idProcesso no HTML da resposta
                link_m = re.search(
                    r'href="([^"]*idProcesso=(\d+)[^"]*)"',
                    post_r.text, re.I
                )
                if link_m:
                    pid  = link_m.group(2)
                    href = link_m.group(1).replace("&amp;", "&")
                    url_proc = href if href.startswith("http") else f"{self.base_url}{href}"
                    _last_auth_log.append(f"  ✓ ID do processo em link HTML: {pid}")
                    return {"id": pid, "idProcesso": pid, "numero": cnj,
                            "_fonte": "web", "_url": url_proc}

                # Procura idProcesso= em qualquer lugar no HTML
                pid_m = re.search(r'idProcesso[="\s:]+(\d+)', post_r.text, re.I)
                if pid_m:
                    pid = pid_m.group(1)
                    _last_auth_log.append(f"  ✓ ID do processo no HTML: {pid}")
                    return {"id": pid, "idProcesso": pid, "numero": cnj, "_fonte": "web"}

                # Numero CNJ aparece no resultado mesmo sem ID explicito
                if cnj[:7] in post_r.text or digitos[:7] in post_r.text:
                    _last_auth_log.append("  ✓ Processo localizado na pagina web (sem ID)")
                    return {"numero": cnj, "_fonte": "web", "_html": post_r.text}

                _last_auth_log.append("  ⚠ Pagina carregou mas processo nao encontrado no HTML")

            except Exception as e:
                _last_auth_log.append(f"  ✗ Erro web {path}: {e}")

        _last_auth_log.append("  ✗ Nao encontrado via REST nem via web")
        return None

    def listar_documentos_web(self, processo_id: str, processo_url: str = "") -> list:
        """Lista documentos via interface web quando a API REST nao esta disponivel."""
        doc_paths = [
            f"/pje/Processo/ConsultaDocumento/listView.seam?idProcesso={processo_id}",
            f"/pje/Processo/DetalheProcesso/listView.seam?idProcesso={processo_id}",
            f"/pje/Processo/ConsultaProcessual/autos.seam?idProcesso={processo_id}",
        ]
        if processo_url and "idProcesso" not in processo_url:
            doc_paths.insert(0, f"{processo_url}&tab=documentos")

        docs = []
        for path in doc_paths:
            try:
                url = path if path.startswith("http") else f"{self.base_url}{path}"
                r = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                _last_auth_log.append(f"  [docs-web] GET {path[:80]} → {r.status_code}")
                if r.status_code != 200 or len(r.text) < 500:
                    continue

                # Links de documentos: idDocumento=XXXXX
                doc_links = re.findall(
                    r'href="([^"]*idDocumento=(\d+)[^"]*)"',
                    r.text, re.I
                )
                if doc_links:
                    seen = set()
                    for href, doc_id in doc_links:
                        if doc_id in seen:
                            continue
                        seen.add(doc_id)
                        doc_url = href.replace("&amp;", "&")
                        if not doc_url.startswith("http"):
                            doc_url = f"{self.base_url}{doc_url}"
                        docs.append({
                            "id":      doc_id,
                            "tipo":    "",
                            "nome":    f"Documento {doc_id}",
                            "data":    "",
                            "autor":   "",
                            "url_pdf": doc_url,
                        })
                    _last_auth_log.append(f"  ✓ {len(docs)} documento(s) encontrado(s) via web")
                    return docs

                _last_auth_log.append("  ⚠ Pagina carregou mas sem links de documentos")
            except Exception as e:
                _last_auth_log.append(f"  ✗ Erro docs-web {path}: {e}")

        return docs

    def listar_documentos(self, processo_id: str, processo_url: str = "") -> list:
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
        # Fallback: scraping da interface web
        _last_auth_log.append("  → REST documentos indisponivel; tentando interface web...")
        return self.listar_documentos_web(processo_id, processo_url)

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
