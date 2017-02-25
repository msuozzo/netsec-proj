from Crypto.Cipher import AES
from Crypto.Hash import SHA256

_AES_IV = '0' * 16


def pkcs7_pad(plaintext):
  length = 16 - (len(plaintext) % 16)
  plaintext += bytes([length]) * length
  return plaintext


def pkcs7_unpad(plaintext):
  return plaintext[:-plaintext[-1]]


def encrypt(plaintext, key):
  cipher = AES.new(key=key, mode=AES.MODE_CBC, IV=_AES_IV)
  padded_plaintext = pkcs7_pad(plaintext)
  return cipher.encrypt(padded_plaintext)


def decrypt(ciphertext, key):
  cipher = AES.new(key=key, mode=AES.MODE_CBC, IV=_AES_IV)
  padded_plaintext = cipher.decrypt(ciphertext)
  return pkcs7_unpad(padded_plaintext)


def hash_(input_):
  state = SHA256.new()
  state.update(input_)
  return state.digest()
