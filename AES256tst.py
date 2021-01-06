from AES256 import AESCipher

if __name__ == "__main__":
    enc = AESCipher('def', '123456')
    res = enc.encrypt('def')
    print("encryption: ", res)
    res = enc.decrypt(enc, res)
    print("decryption:------", res)
