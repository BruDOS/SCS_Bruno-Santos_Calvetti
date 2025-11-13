from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

# --- Função para derivar chave AES a partir de uma master key ---
def ChaveDerivada(ChavePrincipal: bytes, salt: bytes = None, length: int = 32, iterations: int = 300_000):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations
    )
    derived_key = kdf.derive(ChavePrincipal)
    return derived_key, salt

# --- Funções AES-GCM ---
def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ct

def decrypt_aes_gcm(key: bytes, blob: bytes, associated_data: bytes = None) -> bytes:
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data)

if __name__ == "__main__":
    senhas = [b"senha123", b"minhaSenhaSecreta!", b"admin2025"]

    # Master key de 64 bytes
    ChavePrincipal = os.urandom(64)

    # Derivar chave AES de 32 bytes
    aes_key, salt = ChaveDerivada(ChavePrincipal)

    print("=== SENHAS EM TEXTO CLARO ===")
    for s in senhas:
        print(s.decode())

    print("\n=== SENHAS CRIPTOGRAFADAS (base64) ===")
    blobs = []
    for s in senhas:
        encrypted = encrypt_aes_gcm(aes_key, s)
        blobs.append(encrypted)
        print(base64.b64encode(encrypted).decode())

    print("\n=== SENHAS RECUPERADAS ===")
    for b in blobs:
        decrypted = decrypt_aes_gcm(aes_key, b)
        print(decrypted.decode())
