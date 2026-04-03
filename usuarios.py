"""
Gerenciamento de usuarios para o app PJe.
Senhas armazenadas com hash bcrypt — nunca em texto puro.

Para adicionar/remover usuarios, edite o dicionario USUARIOS abaixo
ou use as funcoes auxiliares no final deste arquivo.
"""

import bcrypt
import json
import os

# ── Arquivo de persistencia ───────────────────────────────────────────────────
_USUARIOS_FILE = os.path.join(os.path.dirname(__file__), "usuarios_db.json")


def _carregar_db() -> dict:
    if os.path.exists(_USUARIOS_FILE):
        with open(_USUARIOS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _salvar_db(db: dict):
    with open(_USUARIOS_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


# ── Operacoes de usuario ──────────────────────────────────────────────────────

def criar_usuario(username: str, senha: str, nome: str = "", perfil: str = "usuario") -> bool:
    """Cria usuario com senha hasheada. Retorna False se ja existir."""
    db = _carregar_db()
    if username in db:
        return False
    hash_senha = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()
    db[username] = {
        "nome":   nome or username,
        "hash":   hash_senha,
        "perfil": perfil,  # "admin" ou "usuario"
        "ativo":  True,
    }
    _salvar_db(db)
    return True


def alterar_senha(username: str, nova_senha: str) -> bool:
    db = _carregar_db()
    if username not in db:
        return False
    db[username]["hash"] = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt()).decode()
    _salvar_db(db)
    return True


def remover_usuario(username: str) -> bool:
    db = _carregar_db()
    if username not in db:
        return False
    del db[username]
    _salvar_db(db)
    return True


def listar_usuarios() -> list:
    db = _carregar_db()
    return [
        {"username": u, "nome": d["nome"], "perfil": d["perfil"], "ativo": d["ativo"]}
        for u, d in db.items()
    ]


def autenticar(username: str, senha: str) -> dict | None:
    """
    Verifica credenciais. Retorna dados do usuario se valido, None se invalido.
    """
    db = _carregar_db()
    user = db.get(username)
    if not user or not user.get("ativo", True):
        return None
    if bcrypt.checkpw(senha.encode(), user["hash"].encode()):
        return {"username": username, "nome": user["nome"], "perfil": user["perfil"]}
    return None


def inicializar_usuarios_padrao():
    """Cria usuarios iniciais se o banco estiver vazio."""
    db = _carregar_db()
    if not db:
        criar_usuario("admin",  "Admin@2024",  nome="Administrador", perfil="admin")
        criar_usuario("teste",  "Teste@2024",  nome="Usuario Teste", perfil="usuario")


# ── Executa inicializacao ao importar ─────────────────────────────────────────
inicializar_usuarios_padrao()
