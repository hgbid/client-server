import base64
from base64 import b64encode

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

""" NOTE: in Lib\site-packages
folder name: crypto > Crypto """

from Crypto.Cipher import AES, PKCS1_OAEP


def generate_aes(pub_key):
    public_key_bytes = base64.b64decode(pub_key)
    rsa_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(rsa_key)  # RSA

    aes_key = get_random_bytes(16)
    aes_key_b64 = str(base64.b64encode(aes_key)).replace('b\'', '').replace('==\'', '==')
    print("- AES key generated.")
    encrypted_aes_key = base64.b64encode(cipher.encrypt(aes_key) + b'==')

    return aes_key_b64, encrypted_aes_key


def decrypted_aes_message(cipher, data):
    encrypted_message = base64.b64decode(data)
    decrypted_message = cipher.decrypt(encrypted_message)
    unpadded_message = unpad(decrypted_message, AES.block_size)
    return unpadded_message


def crc32(filename):
    with open("files/" + filename, 'rb') as f:
        buf = f.read()
        crc = binascii.crc32(buf) & 0xFFFFFFFF
        return format(((crc << 24) & 0xFF000000) |
                      ((crc << 8) & 0x00FF0000) |
                      ((crc >> 8) & 0x0000FF00) |
                      ((crc >> 24) & 0x000000FF), '08x')

