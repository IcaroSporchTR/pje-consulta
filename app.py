"""
Consulta de Processos PJe
Fontes: DataJud (CNJ) para dados publicos + PJe autenticado para documentos

Execucao:
    pip install -r requirements.txt
    streamlit run app.py
"""

import streamlit as st
import pandas as pd
from tribunais import TRIBUNAIS, sigla_options, detect_tribunal_from_numero
from datajud_client import (
    buscar_processo,
    buscar_em_todos_tribunais,
    extrair_dados_basicos,
    extrair_partes,
    extrair_movimentos,
    extrair_documentos,
)
from pje_client import PjeClient, get_auth_log
from cert_utils import CertificadoA1
from usuarios import autenticar, criar_usuario, alterar_senha, remover_usuario, listar_usuarios

st.set_page_config(
    page_title="Consulta PJe",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.block-container { padding-top: 1.5rem; }
.stTabs [data-baseweb="tab"] { font-size: 0.95rem; }
.login-box { max-width: 380px; margin: 80px auto; padding: 2rem;
             border: 1px solid #333; border-radius: 12px; background: #1e2130; }
</style>
""", unsafe_allow_html=True)

# ── Tela de Login ─────────────────────────────────────────────────────────────
if "usuario_logado" not in st.session_state:
    st.session_state.usuario_logado = None
if "pje_otp_pending" not in st.session_state:
    st.session_state.pje_otp_pending = False
if "pje_client_otp" not in st.session_state:
    st.session_state.pje_client_otp = None
if "pje_otp_sigla" not in st.session_state:
    st.session_state.pje_otp_sigla = None
if "pje_auth_cliente" not in st.session_state:
    st.session_state.pje_auth_cliente = {}  # sigla -> PjeClient autenticado

if not st.session_state.usuario_logado:
    st.markdown("<div class='login-box'>", unsafe_allow_html=True)
    st.title("⚖️ Consulta PJe")
    st.subheader("Acesso ao Sistema")
    login_user  = st.text_input("Usuario", placeholder="Digite seu usuario")
    login_senha = st.text_input("Senha", type="password", placeholder="Digite sua senha")
    col_btn, col_msg = st.columns([1, 2])
    with col_btn:
        btn_login = st.button("Entrar", type="primary", use_container_width=True)
    if btn_login:
        if not login_user or not login_senha:
            st.warning("Preencha usuario e senha.")
        else:
            user_data = autenticar(login_user.strip(), login_senha)
            if user_data:
                st.session_state.usuario_logado = user_data
                st.rerun()
            else:
                st.error("Usuario ou senha incorretos.")
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# Usuario logado — exibe info no sidebar
usuario_atual = st.session_state.usuario_logado
st.sidebar.markdown(f"**Bem-vindo, {usuario_atual['nome']}**")
st.sidebar.caption(f"Perfil: {usuario_atual['perfil']}")
if st.sidebar.button("Sair"):
    st.session_state.usuario_logado = None
    st.rerun()
st.sidebar.markdown("---")

# ── Sidebar — Credenciais ─────────────────────────────────────────────────────
st.sidebar.header("Credenciais")

st.sidebar.subheader("DataJud (CNJ)")
st.sidebar.markdown(
    "Obtenha sua chave em: [datajud.cnj.jus.br](https://www.cnj.jus.br/sistemas/datajud/)",
    unsafe_allow_html=False,
)
# Chave publica vigente publicada em: https://datajud-wiki.cnj.jus.br/api-publica/acesso/
DATAJUD_KEY_PUBLICA = "cDZHYzlZa0JadVREZDJCendQbXY6SkJlTzNjLV9TRENyQk1RdnFKZGRQdw=="

datajud_key = st.sidebar.text_input(
    "API Key DataJud",
    value=DATAJUD_KEY_PUBLICA,
    help="Chave publica vigente do CNJ. Pode ser alterada pelo CNJ a qualquer momento.",
)

st.sidebar.markdown("---")
st.sidebar.subheader("PJe (para documentos)")

auth_modo = st.sidebar.radio(
    "Forma de autenticacao",
    ["Certificado Digital (A1)", "Usuario e Senha"],
    index=0,
)

cert_obj    = None
pje_usuario = ""
pje_senha   = ""
pje_otp     = ""

if auth_modo == "Certificado Digital (A1)":
    pfx_file = st.sidebar.file_uploader(
        "Certificado A1 (.pfx ou .p12)",
        type=["pfx", "p12"],
        help="Arquivo do certificado e-CPF, e-CNPJ ou OAB (tipo A1)",
    )
    cert_senha = st.sidebar.text_input("Senha do certificado", type="password")

    if pfx_file and cert_senha:
        try:
            cert_obj = CertificadoA1(pfx_file.read(), cert_senha)
            info = cert_obj.info
            st.sidebar.success(
                f"Certificado carregado\n\n"
                f"**Titular:** {info.get('titular','—')}\n\n"
                f"**Validade:** {info.get('validade','—')}"
            )
        except Exception as e:
            st.sidebar.error(f"Erro ao ler certificado: {e}")
            cert_obj = None
    elif pfx_file and not cert_senha:
        st.sidebar.info("Informe a senha do certificado.")
else:
    pje_usuario = st.sidebar.text_input("Usuario PJe (CPF, so numeros)")
    pje_senha   = st.sidebar.text_input("Senha PJe", type="password")
    pje_otp     = st.sidebar.text_input(
        "Segundo Fator (OTP)",
        placeholder="Codigo do autenticador (se exigido)",
        key="pje_otp_sidebar",
        max_chars=8,
    )

    # ── Status de conexao ────────────────────────────────────────────────────
    _conectados = list(st.session_state.get("pje_auth_cliente", {}).keys())
    if _conectados:
        st.sidebar.success(f"Conectado: {', '.join(_conectados)}")
    elif st.session_state.get("pje_otp_pending"):
        st.sidebar.warning("OTP exigido — preencha o codigo e clique Conectar")
    else:
        st.sidebar.info("Nao conectado ao PJe")

    btn_conectar = st.sidebar.button("Conectar ao PJe", key="btn_conectar_pje", use_container_width=True)
    if btn_conectar:
        if not pje_usuario or not pje_senha:
            st.sidebar.warning("Preencha usuario e senha.")
        else:
            _sigla_pre = (
                st.session_state.get("pje_otp_sigla")
                or next(iter(st.session_state.get("pje_resultados") or []), (None,))[0]
                or "TJMG"
            )
            _info_pre = TRIBUNAIS.get(_sigla_pre)
            if not _info_pre:
                st.sidebar.error(f"Tribunal {_sigla_pre} nao mapeado.")
            else:
                with st.sidebar.status("Conectando...", expanded=True) as _status:
                    _client_pre = PjeClient(_info_pre[1])
                    _res = _client_pre.autenticar_com_senha(pje_usuario, pje_senha, pje_otp)
                    _log_pre = get_auth_log()
                    if _res is True:
                        st.session_state.pje_auth_cliente[_sigla_pre] = _client_pre
                        st.session_state.pje_otp_pending  = False
                        st.session_state.pje_resultados   = []
                        st.session_state.pje_numero_buscado = ""
                        _status.update(label=f"Conectado ao {_sigla_pre}!", state="complete")
                        st.rerun()
                    elif _res == "otp_required":
                        _status.update(label="OTP exigido — preencha o codigo acima e clique Conectar novamente.", state="error")
                        st.session_state.pje_otp_pending = True
                        st.session_state.pje_otp_sigla   = _sigla_pre
                        st.session_state.pje_client_otp  = _client_pre
                    else:
                        _status.update(label="Falha na autenticacao — veja o log abaixo.", state="error")
                    if _log_pre and _res is not True:
                        st.session_state["_ultimo_log_auth"] = _log_pre

# ── Corpo principal ───────────────────────────────────────────────────────────
st.title("⚖️ Consulta de Processos PJe")

col1, col2, col3 = st.columns([4, 2, 1])

with col1:
    numero_input = st.text_input(
        "Numero do processo (formato CNJ)",
        placeholder="0001234-56.2023.8.26.0001",
    )

with col2:
    opcoes = [("AUTO", "Detectar automaticamente")] + sigla_options()
    sigla_sel = st.selectbox(
        "Tribunal",
        options=[s for s, _ in opcoes],
        format_func=lambda s: next(d for sig, d in opcoes if sig == s),
    )

with col3:
    buscar_todos = st.checkbox("Buscar em todos", value=True, help="Pesquisa em todos os tribunais (mais lento)")

btn_buscar = st.button("Buscar", type="primary", use_container_width=True)

# ── Execucao da busca ─────────────────────────────────────────────────────────
if btn_buscar:
    if not numero_input.strip():
        st.warning("Informe o numero do processo.")
        st.stop()

    if not datajud_key:
        st.warning(
            "Informe a API Key do DataJud na sidebar para buscar dados publicos.\n\n"
            "Registro gratuito em: https://www.cnj.jus.br/sistemas/datajud/"
        )
        st.stop()

    numero = numero_input.strip()

    if buscar_todos:
        indices_busca = [(sig, v[2]) for sig, v in TRIBUNAIS.items()]
        with st.spinner("Buscando em todos os tribunais..."):
            resultados = buscar_em_todos_tribunais(numero, indices_busca, datajud_key)
    else:
        tribunal_sigla = sigla_sel
        if tribunal_sigla == "AUTO":
            tribunal_sigla = detect_tribunal_from_numero(numero)
            if not tribunal_sigla:
                st.error("Nao foi possivel detectar o tribunal pelo numero. Selecione manualmente.")
                st.stop()
            st.info(f"Tribunal detectado: **{tribunal_sigla}**")

        info = TRIBUNAIS.get(tribunal_sigla)
        if not info:
            st.error(f"Tribunal {tribunal_sigla} nao encontrado.")
            st.stop()

        indice = info[2]
        with st.spinner(f"Buscando em {tribunal_sigla}..."):
            try:
                doc = buscar_processo(numero, indice, datajud_key)
            except Exception as e:
                st.error(f"Erro na consulta DataJud: {e}")
                st.stop()

        if not doc:
            st.warning(f"Processo nao encontrado no {tribunal_sigla} via DataJud.")
            st.stop()

        resultados = [(tribunal_sigla, doc)]

    if not resultados:
        st.warning("Processo nao encontrado em nenhum tribunal consultado.")
        st.stop()

    # Persiste resultados no session_state para sobreviver reruns (OTP, etc.)
    st.session_state.pje_resultados     = resultados
    st.session_state.pje_numero_buscado = numero
    # Nova busca descarta OTP pendente de busca anterior (mantém pre_auth ja confirmado)
    st.session_state.pje_otp_pending = False
    st.session_state.pje_client_otp  = None

# ── Exibe resultados (sempre a partir do session_state) ───────────────────────
_resultados = st.session_state.get("pje_resultados", [])
_numero     = st.session_state.get("pje_numero_buscado", "")

for sigla, doc in _resultados:
    tribunal_nome = TRIBUNAIS.get(sigla, ("", "", ""))[0] if sigla in TRIBUNAIS else sigla
    st.markdown(f"## {sigla} — {tribunal_nome}")

    basicos      = extrair_dados_basicos(doc)
    partes       = extrair_partes(doc)
    movs         = extrair_movimentos(doc)
    docs_datajud = extrair_documentos(doc)

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Numero",         basicos["numero"] or _numero)
    k2.metric("Classe",         basicos["classe"] or "—")
    k3.metric("Orgao Julgador", basicos["orgao"]  or "—")
    k4.metric("Ajuizamento",    basicos["data_ajuiz"] or "—")
    k5.metric("Documentos",     len(docs_datajud) if docs_datajud else "Via PJe")

    tab_dados, tab_partes, tab_movimentos, tab_docs_datajud, tab_documentos = st.tabs(
        ["Dados Basicos", "Partes", "Movimentacoes", "Documentos (DataJud)", "Documentos (PJe autenticado)"]
    )

    # ── Dados basicos ─────────────────────────────────────────────────────────
    with tab_dados:
        with st.expander("JSON completo do processo (todos os campos)", expanded=False):
            st.json(doc)
        col_a, col_b = st.columns(2)
        with col_a:
            st.write("**Numero**",          basicos["numero"] or _numero)
            st.write("**Classe**",           f"{basicos['classe']} (cod. {basicos['classe_codigo']})" if basicos['classe_codigo'] else basicos['classe'] or "—")
            st.write("**Grau**",             basicos["grau"]   or "—")
            st.write("**Tribunal**",         basicos["tribunal"] or sigla)
            st.write("**Sistema**",          basicos["sistema"] or "—")
            st.write("**Formato**",          basicos["formato"] or "—")
            st.write("**Nivel de Sigilo**",  basicos["nivel_sigilo"])
            st.write("**Prioridade**",       basicos["prioridade"] or "—")
        with col_b:
            st.write("**Orgao Julgador**",   basicos["orgao"] or "—")
            st.write("**Codigo Orgao**",     basicos["orgao_codigo"] or "—")
            st.write("**Municipio/UF**",     f"{basicos['orgao_municipio']} / {basicos['orgao_uf']}" if basicos['orgao_municipio'] else "—")
            st.write("**Ajuizamento**",      basicos["data_ajuiz"]  or "—")
            st.write("**Ultima atualizacao**", basicos["ultima_atualiz"] or "—")
            st.write("**Valor da Causa**",   basicos["valor_causa"] or "—")
            st.write("**Assuntos**",         " | ".join(basicos["assuntos"]) or "—")

    # ── Partes ────────────────────────────────────────────────────────────────
    with tab_partes:
        if not partes:
            st.info("Nenhuma parte encontrada.")
        else:
            for polo_label in ["ATIVO", "PASSIVO", "TERCEIRO", "TESTEMUNHA"]:
                grupo = [p for p in partes if p["polo"].upper() == polo_label]
                if not grupo:
                    continue
                st.subheader(polo_label)
                for p in grupo:
                    with st.expander(f"**{p['nome']}**" + (f"  —  {p['documento']}" if p['documento'] else "")):
                        if p["advogados"]:
                            st.write("**Advogados:**")
                            for adv in p["advogados"]:
                                oab = f" (OAB: {adv['oab']})" if adv["oab"] else ""
                                st.write(f"- {adv['nome']}{oab}")
                        else:
                            st.write("Sem advogados cadastrados.")
            outros = [p for p in partes if p["polo"].upper() not in ["ATIVO","PASSIVO","TERCEIRO","TESTEMUNHA"]]
            for p in outros:
                st.write(f"**{p['polo'].upper()}**: {p['nome']}")

    # ── Movimentacoes ─────────────────────────────────────────────────────────
    with tab_movimentos:
        if not movs:
            st.info("Nenhuma movimentacao encontrada.")
        else:
            st.write(f"**{len(movs)} movimentacao(oes) encontrada(s)**")
            df_movs = pd.DataFrame(movs)
            df_movs.columns = ["Data", "Codigo", "Nome", "Complemento"]
            st.dataframe(df_movs[["Data", "Nome", "Complemento"]], use_container_width=True, height=400)
            st.download_button(
                "Exportar movimentacoes CSV",
                data=df_movs.to_csv(index=False).encode("utf-8"),
                file_name=f"movimentacoes_{_numero.replace('.','').replace('-','')}.csv",
                mime="text/csv",
            )

    # ── Documentos DataJud ────────────────────────────────────────────────────
    with tab_docs_datajud:
        if not docs_datajud:
            st.info(
                "Este tribunal nao envia documentos via DataJud (API publica).\n\n"
                "Use a aba **Documentos (PJe autenticado)** com certificado digital para acessar as pecas."
            )
        else:
            st.write(f"**{len(docs_datajud)} documento(s) retornado(s) pelo DataJud**")
            for d in docs_datajud:
                sigilo_label = f" [SIGILO {d['sigilo']}]" if d['sigilo'] else ""
                titulo = d['titulo'] or d['tipo'] or f"Documento {d['id']}"
                with st.expander(f"[{d['data']}] {titulo}{sigilo_label}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**ID**",         d["id"]          or "—")
                        st.write("**Tipo**",        d["tipo"]        or "—")
                        st.write("**Cod. Tipo**",   d["tipo_codigo"] or "—")
                        st.write("**Titulo**",      d["titulo"]      or "—")
                    with col2:
                        st.write("**Data**",        d["data"]        or "—")
                        st.write("**Autor**",       d["autor"]       or "—")
                        st.write("**Polo**",        d["polo"]        or "—")
                        st.write("**Paginas**",     d["paginas"]     or "—")
                        st.write("**Hash**",        d["hash"]        or "—")
                    if d["vinculados"]:
                        st.write("**Documentos vinculados:**")
                        for v in d["vinculados"]:
                            st.write(f"- [{v['tipo']}] {v['titulo']} (id: {v['id']})")
            df_docs = pd.DataFrame([{
                "ID": d["id"], "Tipo": d["tipo"], "Titulo": d["titulo"],
                "Data": d["data"], "Autor": d["autor"], "Polo": d["polo"],
                "Paginas": d["paginas"], "Sigilo": d["sigilo"], "Hash": d["hash"],
            } for d in docs_datajud])
            st.download_button(
                "Exportar documentos CSV",
                data=df_docs.to_csv(index=False).encode("utf-8"),
                file_name=f"documentos_{_numero.replace('.','').replace('-','')}.csv",
                mime="text/csv",
            )

    # ── Documentos via PJe autenticado ────────────────────────────────────────
    with tab_documentos:
        tem_credencial = (cert_obj is not None) or (pje_usuario and pje_senha)

        if not tem_credencial:
            st.info(
                "Configure a autenticacao PJe na sidebar para acessar documentos.\n\n"
                "**Opcoes:** Certificado Digital A1 (.pfx/.p12) ou Usuario e Senha.\n\n"
                "Movimentacoes e partes ja estao disponiveis acima via DataJud (sem login)."
            )
        else:
            info_tribunal = TRIBUNAIS.get(sigla)
            if not info_tribunal:
                st.warning(f"URL do PJe para {sigla} nao mapeada.")
            else:
                pje_url  = info_tribunal[1]
                pre_auth = st.session_state.pje_auth_cliente.get(sigla)
                otp_pend = (st.session_state.pje_otp_pending and
                            st.session_state.pje_otp_sigla == sigla)

                if pre_auth:
                    # Sessao ja autenticada (pos-OTP ou direto)
                    client     = pre_auth
                    ok         = True
                    modo_usado = "usuario e senha (autenticado)"
                elif otp_pend:
                    # OTP solicitado mas ainda nao confirmado — nao re-autentica
                    st.warning("⚠ Segundo fator (OTP) exigido. Insira o codigo abaixo.")
                    ok = False
                else:
                    client = PjeClient(pje_url)
                    with st.spinner(f"Autenticando em {pje_url}..."):
                        if cert_obj is not None:
                            resultado_auth = client.autenticar_com_certificado(cert_obj.cert_tuple)
                            modo_usado     = "certificado digital"
                        else:
                            resultado_auth = client.autenticar_com_senha(pje_usuario, pje_senha, pje_otp)
                            modo_usado     = "usuario e senha"

                    if resultado_auth == "otp_required":
                        st.session_state.pje_otp_pending = True
                        st.session_state.pje_client_otp  = client
                        st.session_state.pje_otp_sigla   = sigla
                        st.warning("⚠ Segundo fator (OTP) exigido. Insira o codigo abaixo.")
                        ok = False
                    else:
                        ok = bool(resultado_auth)

                if ok:
                    st.success(f"Autenticado com sucesso via {modo_usado}.")
                    with st.spinner("Buscando processo no PJe..."):
                        proc_pje = client.buscar_processo(_numero)

                    if not proc_pje:
                        st.warning("Processo nao encontrado via API do PJe autenticado.")
                        pje_url_consulta = f"{pje_url}/pje/ConsultaProcessual/listView.seam"
                        st.info(
                            f"A API REST do TJMG pode nao expor esse endpoint. "
                            f"Voce pode [abrir o processo diretamente no PJe]({pje_url_consulta}) "
                            f"usando a sessao autenticada do navegador."
                        )
                        log_busca = get_auth_log()
                        if log_busca:
                            with st.expander("Log de tentativas de busca", expanded=False):
                                for linha in log_busca:
                                    if "✓" in linha:
                                        st.success(linha)
                                    elif "✗" in linha:
                                        st.error(linha)
                                    elif "⚠" in linha:
                                        st.warning(linha)
                                    else:
                                        st.code(linha, language=None)
                    else:
                        proc_id  = proc_pje.get("id") or proc_pje.get("idProcesso")
                        proc_url = proc_pje.get("_url", "")
                        if not proc_id:
                            st.warning("ID interno do processo nao retornado pelo PJe.")
                        else:
                            with st.spinner("Buscando documentos..."):
                                docs = client.listar_documentos(str(proc_id), proc_url)
                            if not docs:
                                st.info("Nenhum documento encontrado ou acesso restrito ao polo.")
                            else:
                                st.write(f"**{len(docs)} documento(s) encontrado(s)**")
                                for d in docs:
                                    with st.expander(
                                        f"[{d['data'][:10] if d['data'] else ''}] "
                                        f"{d['tipo']} — {d['nome']}"
                                    ):
                                        st.write(f"**Autor:** {d['autor'] or '—'}")
                                        if d["url_pdf"]:
                                            st.markdown(f"[Abrir PDF no PJe]({d['url_pdf']})")
                elif not otp_pend:
                    st.error(f"Falha na autenticacao via {modo_usado}.")
                    log = get_auth_log()
                    if log:
                        with st.expander("Detalhes do erro (log de autenticacao)", expanded=True):
                            for linha in log:
                                if linha.startswith("  ⚠") or "MFA" in linha or "2o FATOR" in linha:
                                    st.warning(linha)
                                elif linha.startswith("  ✓"):
                                    st.success(linha)
                                elif linha.startswith("  ✗") or "Falhou" in linha:
                                    st.error(linha)
                                else:
                                    st.code(linha, language=None)

        if cert_obj is not None:
            try:
                cert_obj.cleanup()
            except Exception:
                pass

    st.markdown("---")

# ── Painel Admin (so para perfil admin) ──────────────────────────────────────
if usuario_atual["perfil"] == "admin":
    st.markdown("---")
    with st.expander("Gerenciamento de Usuarios (Admin)", expanded=False):
        tab_lista, tab_novo, tab_senha, tab_remover = st.tabs(
            ["Listar", "Novo Usuario", "Alterar Senha", "Remover"]
        )

        with tab_lista:
            usuarios = listar_usuarios()
            if usuarios:
                st.dataframe(pd.DataFrame(usuarios), use_container_width=True)
            else:
                st.info("Nenhum usuario cadastrado.")

        with tab_novo:
            nu_user   = st.text_input("Novo usuario (login)")
            nu_nome   = st.text_input("Nome completo")
            nu_senha  = st.text_input("Senha", type="password", key="nu_senha")
            nu_perfil = st.selectbox("Perfil", ["usuario", "admin"])
            if st.button("Criar usuario", key="btn_criar"):
                if not nu_user or not nu_senha:
                    st.warning("Preencha usuario e senha.")
                elif criar_usuario(nu_user.strip(), nu_senha, nome=nu_nome, perfil=nu_perfil):
                    st.success(f"Usuario '{nu_user}' criado com sucesso.")
                else:
                    st.error(f"Usuario '{nu_user}' ja existe.")

        with tab_senha:
            as_user  = st.text_input("Usuario", key="as_user")
            as_senha = st.text_input("Nova senha", type="password", key="as_senha")
            if st.button("Alterar senha", key="btn_alterar"):
                if alterar_senha(as_user.strip(), as_senha):
                    st.success("Senha alterada com sucesso.")
                else:
                    st.error(f"Usuario '{as_user}' nao encontrado.")

        with tab_remover:
            rm_user = st.text_input("Usuario a remover", key="rm_user")
            if st.button("Remover usuario", type="primary", key="btn_remover"):
                if rm_user == usuario_atual["username"]:
                    st.error("Nao e possivel remover o proprio usuario logado.")
                elif remover_usuario(rm_user.strip()):
                    st.success(f"Usuario '{rm_user}' removido.")
                else:
                    st.error(f"Usuario '{rm_user}' nao encontrado.")

# ── Rodape ────────────────────────────────────────────────────────────────────
st.caption(
    "Fontes: API Publica DataJud/CNJ (dados publicos) + PJe por tribunal (documentos autenticados). "
    "Os dados sao de responsabilidade dos respectivos tribunais."
)
