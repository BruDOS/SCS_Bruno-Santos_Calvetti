from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def DerivandoSenha(senha: bytes, salt: bytes = None, iterations: int = 300_000) -> (bytes, bytes): # type: ignore
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    chave = kdf.derive(senha)
    return chave, salt

def CriptografiaAES(chave: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    aesgcm = AESGCM(chave)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ct

def decrypt_aes_gcm(chave: bytes, blob: bytes, associated_data: bytes = None) -> bytes:
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(chave)
    return aesgcm.decrypt(nonce, ct, associated_data)


# --- Test / Verificação ---
if __name__ == "__main__":
    senha = b"minha-senha-super-secreta"
    chave, salt = DerivandoSenha(senha)
    msg = b"Mensagem secreta para cifrar"
    ad = b"header-autenticado"
    blob = CriptografiaAES(chave, msg, associated_data=ad)
    recovered = decrypt_aes_gcm(chave, blob, associated_data=ad)
    assert recovered == msg
    print("AES-GCM: OK — mensagem recuperada corretamente.")
