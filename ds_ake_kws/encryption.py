import base64
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import tempfile


def generate_key_pair():
    """
    Generate an RSA key pair.
    Returns the private key and public key in PEM format.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def encrypt_file(file_content, public_key):
    """
    Encrypt file content using hybrid encryption.
    """
    try:
        symmetric_key = get_random_bytes(16)
        aes_cipher = AES.new(symmetric_key, AES.MODE_EAX)
        encrypted_file_content, tag = aes_cipher.encrypt_and_digest(file_content)

        rsa_public_key = RSA.import_key(public_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
        encrypted_symmetric_key = rsa_cipher.encrypt(symmetric_key)
        encrypted_file_content_b64 = base64.b64encode(encrypted_file_content)
        encrypted_symmetric_key_b64 = base64.b64encode(encrypted_symmetric_key)
        return encrypted_file_content_b64, encrypted_symmetric_key_b64
    except Exception as e:
        print(f"Encryption error: {e}")
        raise


def decrypt_file(encrypted_file_content_b64, encrypted_symmetric_key_b64, private_key):
    """
    Decrypt file content using hybrid decryption.
    """
    try:
        encrypted_file_content = base64.b64decode(encrypted_file_content_b64)
        encrypted_symmetric_key = base64.b64decode(encrypted_symmetric_key_b64)

        rsa_private_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
        symmetric_key = rsa_cipher.decrypt(encrypted_symmetric_key)
        aes_cipher = AES.new(symmetric_key, AES.MODE_EAX)
        decrypted_file_content = aes_cipher.decrypt(encrypted_file_content)

        return decrypted_file_content
    except Exception as e:
        print(f"Decryption error: {e}")
        raise
