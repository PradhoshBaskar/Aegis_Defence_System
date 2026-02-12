"""
AEGIS Quantum Shield -- ML-KEM-768 (Kyber) + AES-256-CBC Hybrid Encryption
Provides server-side key exchange and payload decryption.
"""
import base64
import hashlib
import json

try:
    from kyber_py.ml_kem import ML_KEM_768
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    _KYBER_AVAILABLE = True
except ImportError as e:
    _KYBER_AVAILABLE = False
    print(f"Kyber/PyCryptodome not available: {e}")
    print("   Quantum endpoints will return 503.")


class KyberGuard:
    """
    Hybrid encryption engine:
      ML-KEM-768 (Kyber) for post-quantum key encapsulation
      AES-256-CBC for symmetric data encryption

    API (kyber-py v1.2.0):
      keygen()       -> (ek, dk)       ek=1184B  dk=2400B
      encaps(ek)     -> (ss, ct)       ss=32B    ct=1088B
      decaps(dk, ct) -> ss             ss=32B
    """

    def __init__(self):
        if not _KYBER_AVAILABLE:
            self.ek = None
            self.dk = None
            print("KyberGuard: running in MOCK mode (no crypto)")
            return

        print("INITIALIZING KYBER-768 QUANTUM ENGINE...")
        self.ek, self.dk = ML_KEM_768.keygen()
        print(f"Kyber-768 Keypair Generated (ek={len(self.ek)}B, dk={len(self.dk)}B)")

    @property
    def available(self):
        return _KYBER_AVAILABLE and self.ek is not None

    def get_public_key(self):
        """Return the server encapsulation key (public key) as a Base64 string."""
        if not self.available:
            return None
        return base64.b64encode(self.ek).decode("utf-8")

    def decrypt_payload(self, capsule_b64, iv_b64, ciphertext_b64):
        """
        Full hybrid decryption pipeline:
          1. Base64-decode all inputs
          2. ML_KEM_768.decaps(dk, capsule) -> 32-byte shared secret
          3. SHA-256(shared_secret) -> 32-byte AES key
          4. AES-CBC decrypt + PKCS7 unpad
          5. Return the plaintext JSON string

        Raises ValueError on any decryption failure.
        """
        if not self.available:
            raise ValueError("Kyber engine not initialized")

        capsule = base64.b64decode(capsule_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        shared_secret = ML_KEM_768.decaps(self.dk, capsule)
        aes_key = hashlib.sha256(shared_secret).digest()

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)

        plaintext = unpad(padded_plaintext, AES.block_size)
        return plaintext.decode("utf-8")


kyber_engine = KyberGuard()