"""
Utilitarios para certificado digital A1 (PFX/P12).

Extrai cert + chave privada do arquivo PFX e grava arquivos PEM
temporarios para uso com requests (mTLS).

Tipos suportados:
  - A1: arquivo .pfx / .p12 protegido por senha
  - A3: token/smartcard (requer driver PKCS#11 — ver instrucoes ao final)
"""

import os
import tempfile
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


class CertificadoA1:
    """
    Carrega um certificado A1 (PFX/P12) e disponibiliza os arquivos PEM
    temporarios necessarios para autenticacao mTLS com requests.
    """

    def __init__(self, pfx_bytes: bytes, senha: str):
        self._pfx_bytes = pfx_bytes
        self._senha_bytes = senha.encode() if isinstance(senha, str) else senha
        self._tmp_cert = None
        self._tmp_key = None
        self._info = {}
        self._carregar()

    def _carregar(self):
        chave, cert, cadeia = load_key_and_certificates(
            self._pfx_bytes, self._senha_bytes
        )

        # Extrai informacoes do titular
        try:
            subject = {attr.oid.dotted_string: attr.value for attr in cert.subject}
            # OID 2.5.4.3 = CN (Common Name)
            self._info["titular"] = subject.get("2.5.4.3", "")
            self._info["validade"] = cert.not_valid_after_utc.strftime("%d/%m/%Y")
            self._info["emissor"] = str(cert.issuer)
        except Exception:
            pass

        # Grava arquivos PEM temporarios
        cert_pem = cert.public_bytes(Encoding.PEM)
        key_pem  = chave.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

        # Cadeia de CA (intermediarias)
        chain_pem = b""
        if cadeia:
            for ca in cadeia:
                chain_pem += ca.public_bytes(Encoding.PEM)

        self._tmp_cert = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        self._tmp_cert.write(cert_pem + chain_pem)
        self._tmp_cert.flush()

        self._tmp_key = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        self._tmp_key.write(key_pem)
        self._tmp_key.flush()

    @property
    def cert_path(self) -> str:
        return self._tmp_cert.name

    @property
    def key_path(self) -> str:
        return self._tmp_key.name

    @property
    def cert_tuple(self) -> tuple:
        """Formato aceito por requests: cert=(cert_path, key_path)"""
        return (self.cert_path, self.key_path)

    @property
    def info(self) -> dict:
        return self._info

    def cleanup(self):
        """Remove arquivos PEM temporarios."""
        for f in [self._tmp_cert, self._tmp_key]:
            if f:
                try:
                    f.close()
                    os.unlink(f.name)
                except Exception:
                    pass


# ── Instrucoes para A3 (token/smartcard) ─────────────────────────────────────
#
# Certificados A3 ficam em hardware (token USB ou smartcard) e requerem:
#   1. Driver do fabricante instalado (ex: SafeNet, eToken, Watchdata)
#   2. Biblioteca PKCS#11 (.dll no Windows)
#   3. pip install python-pkcs11
#
# Exemplo de uso (apos instalacao):
#
#   import pkcs11
#   lib = pkcs11.lib("C:/Windows/System32/eTPKCS11.dll")
#   token = lib.get_token(token_label="meu_token")
#   with token.open(user_pin="1234") as session:
#       # extrair cert e chave para uso com requests
#       ...
#
# Por ser dependente do hardware e driver especifico, o suporte a A3
# precisa ser configurado caso a caso.
