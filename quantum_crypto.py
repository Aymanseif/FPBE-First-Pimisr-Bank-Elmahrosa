import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
import pqcrypto.kem.kyber512 as kyber  # Kyber 512 - Lattice-Based PQC
import pqcrypto.sign.dilithium2 as dilithium  # Dilithium - PQC Signature

# 🔹 Generate Quantum-Resistant Keypair
def generate_keys():
    public_key, secret_key = kyber.keypair()
    return public_key, secret_key

# 🔹 Encrypt with Quantum-Safe Kyber
def encrypt(message, public_key):
    ciphertext, shared_secret = kyber.enc(public_key)
    cipher = AES.new(shared_secret[:32], AES.MODE_GCM)
    nonce = os.urandom(12)
    cipher.update(nonce)
    encrypted_message, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, nonce, tag, encrypted_message

# 🔹 Decrypt with Quantum-Safe Kyber
def decrypt(ciphertext, secret_key, nonce, tag, encrypted_message):
    shared_secret = kyber.dec(ciphertext, secret_key)
    cipher = AES.new(shared_secret[:32], AES.MODE_GCM, nonce=nonce)
    cipher.update(nonce)
    message = cipher.decrypt_and_verify(encrypted_message, tag)
    return message.decode()

# 🔹 Quantum-Safe Digital Signature with Dilithium
def sign_message(message, secret_key):
    signature = dilithium.sign(message.encode(), secret_key)
    return signature

def verify_signature(message, signature, public_key):
    return dilithium.verify(message.encode(), signature, public_key)

# 🔹 Test PQC Encryption & Signature
if __name__ == "__main__":
    print("🔹 Generating quantum-resistant keys...")
    public_key, secret_key = generate_keys()

    print("🔹 Encrypting message...")
    ciphertext, nonce, tag, encrypted_message = encrypt("Hello, Quantum Future!", public_key)

    print("🔹 Decrypting message...")
    decrypted_message = decrypt(ciphertext, secret_key, nonce, tag, encrypted_message)
    print(f"🔹 Decrypted Message: {decrypted_message}")

    print("🔹 Signing & Verifying...")
    signature = sign_message(decrypted_message, secret_key)
    verified = verify_signature(decrypted_message, signature, public_key)
    print(f"🔹 Signature Verified: {verified}")
