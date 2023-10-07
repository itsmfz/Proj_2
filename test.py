import os
from test1 import (genkey, print_Key, write_to_file, read_from_file, write_hex_data_to_file, read_hex_data_from_file, unpad, pad, read_plain_text, aes_encrypt_block, aes_decrypt_block, result)

def decrypt():
    secret_key = read_from_file()
    print("SECRET KEY READ")
    print_Key(secret_key)

    ciphertext = read_hex_data_from_file(ciphertext_file)
    initialization_vector = read_from_hex_file(iv_file)

    decrypted_text = decrypt_aes_cbc(ciphertext, secret_key, initialization_vector)
    print("DECRYPTED TEXT:", decrypted_text)
    result(decrypted_text)

def testing():
    skey = genkey()
    print_Key(skey)

print("hello")
decrypt()
