import base64
import hmac, hashlib
from Crypto import Random
from Crypto.Cipher import AES
import binascii

class AESCipher(object):

    def __init__(self, key, hkey):
        self.key = hashlib.sha256(key.encode()).digest()
        self.hkey = hkey

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encdata = base64.b64encode(iv + cipher.encrypt(raw.encode()))
        encdata_hash = binascii.hexlify(hmac.new(self.hkey.encode(), encdata, digestmod=hashlib.sha256).digest())
        return encdata_hash + encdata

    def decrypt(self, enc):
        enc = enc[64::] #always 64 -> sha256
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]