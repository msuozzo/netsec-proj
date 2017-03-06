#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def encrypt_file(
    key,
    input_filename,
    output_filename=None,
    chunksize=64 * 1024,
    ):
    """
    Encrypts a file using AES with CBC mode.
....Args:
          key: The encryption key - a string that must be
               either 16, 24 or 32 bytes long. Longer keys
               are more secure.
          input_filename: Name of the input file
          output_filename: If None, '<input_filename>.encrypted' will be used.
          chunksize: Sets the size of the chunk which the function
 ........     uses to read and encrypt the file. Larger chunk
                     sizes can be faster for some files and machines.
                     chunksize must be divisible by 16.
    """
    random.seed(key) #Seed using password.
    rand_key = format(random.getrandbits(16) + (1 << 16), '16b') #Ref 1
    key = rand_key[:16] #Take only 16 bits for AES Key.
    if not output_filename:
        output_filename = input_filename + '.encrypted'

    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = str(os.path.getsize(input_filename)).zfill(16)

    with open(input_filename, 'rb') as infile:
        with open(output_filename, 'wb') as outfile:
            outfile.write(str.encode(filesize))
            outfile.write(iv)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(
    key,
    input_filename,
    output_filename=None,
    chunksize=64 * 1024,
    ):
    """ Decrypts a file using AES with CBC mode.
        Args:
          key: The encryption key - a string that must be
               either 16, 24 or 32 bytes long. Longer keys
               are more secure.
          input_filename: Name of the (encrypted) input file
                          output_filename:
                          If None, the file is named is "decrypted".
          chunksize: Sets the size of the chunk which the function
                     uses to read and encrypt the file. Larger chunk
                     sizes can be faster for some files and machines.
                     chunksize must be divisible by 16.
    """
    random.seed(key) #Seed using password.
    rand_key = format(random.getrandbits(16) + (1 << 16), '16b') #Ref 1
    key = rand_key[:16] #Take only 16 bits for AES Key.
    if not output_filename:
        output_filename = input_filename[:-10]
    try:
        with open(input_filename, 'rb') as infile:
            filesize = str(infile.read(16),'utf-8')
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)
            with open(output_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))
                outfile.truncate(int(filesize))
        return True
    except Exception as e:
        return False

def hash_(filename):
    with open(filename,'rb') as f:
        message = f.read()
        h = SHA256.new()
        h.update(message)
        return h.hexdigest()
