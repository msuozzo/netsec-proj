"""Crypto operations used by the client and server."""

import os
import random

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


_DEFAULT_CHUNK_SIZE = 64 * 1024

def _chunk_file(fd, chunksize):
    """Generator over a file's contents in chunks of a given size."""
    while True:
        data = fd.read(chunksize)
        if data:
            yield data
        else:
            raise StopIteration


def _pkcs7_pad(plaintext):
  length = 16 - (len(plaintext) % 16)
  plaintext += bytes([length]) * length
  return plaintext


def _key_from_password(password):
    """Generates a 128-bit key by seeding an RNG with the provided password."""
    random.seed(password)
    key_bits = random.getrandbits(128)
    return key_bits.to_bytes(16, byteorder='big')


def encrypt_file(
        key, input_filename, output_filename=None,
        chunksize=_DEFAULT_CHUNK_SIZE):
    """Encrypts a file using AES with CBC mode.

    Args:
        key: The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys are more secure.
        input_filename: Name of the input file
        output_filename: If None, '<input_filename>.encrypted' will be used.
        chunksize: Sets the size of the chunk which the function uses to read
            and encrypt the file. Larger chunk sizes can be faster for some files
            and machines. chunksize must be divisible by 16.
    """
    key = _key_from_password(key)
    if not output_filename:
        output_filename = input_filename + '.encrypted'

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    filesize = str(os.path.getsize(input_filename)).zfill(64)

    with open(input_filename, 'rb') as infile:
        with open(output_filename, 'wb') as outfile:
            outfile.write(str.encode(filesize))
            outfile.write(iv)
            for chunk in _chunk_file(infile, chunksize):
                if len(chunk) % 16 != 0:
                    chunk = _pkcs7_pad(chunk)
                outfile.write(cipher.encrypt(chunk))


def decrypt_file(
        key, input_filename, output_filename=None,
        chunksize=_DEFAULT_CHUNK_SIZE):
    """Decrypts a file using AES with CBC mode.

    Args:
        key: The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys are more secure.
        input_filename: Name of the (encrypted) input file
        output_filename: If None, the file is named is "decrypted".
        chunksize: Sets the size of the chunk which the function uses to read
            and encrypt the file. Larger chunk sizes can be faster for some
            files and machines. chunksize must be divisible by 16.
    """
    key = _key_from_password(key)
    if not output_filename:
        output_filename = input_filename[:-10]
    try:
        with open(input_filename, 'rb') as infile:
            with open(output_filename, 'wb') as outfile:
                filesize = int(str(infile.read(64), 'utf-8'))
                iv = infile.read(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                for chunk in _chunk_file(infile, chunksize):
                    outfile.write(cipher.decrypt(chunk))
                outfile.truncate(filesize)
        return True
    except Exception as e:
        return False


def hash_(filename):
    """Returns a hash of the contents of the file."""
    with open(filename,'rb') as f:
        message = f.read()
        h = SHA256.new()
        h.update(message)
        return h.hexdigest()
