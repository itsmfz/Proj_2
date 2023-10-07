import os
from func import (write_key_to_file, genkey, print_Key, write_to_file, read_from_file, write_hex_data_to_file, read_hex_data_from_file, unpad, pad, read_plain_text, aes_encrypt_block, aes_decrypt_block, result)

cipher_text = 'data/ciphertext.txt'
iv = 'data/iv.txt'
s_key = 'data/key.txt'

print(read_from_file(cipher_text))
def decrypt_aes_cbc(cipher, key, ini_v):
    block_size = 16
    previous_block = ini_v
    plaintext = b''

    for i in range(0, len(cipher), block_size):
        block = cipher[i:i + block_size]
        decrypted_block = aes_decrypt_block(block, key)
        plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, previous_block))
        plaintext += plaintext_block
        print(plaintext)
        previous_block = block

    return unpad(plaintext).decode('utf-8')

def decrypt():
    secret_key = read_from_file(s_key)
    print("SECRET KEY READ")
    print_Key(secret_key)

    ciphertext = read_hex_data_from_file(cipher_text)
    initialization_vector = read_hex_data_from_file(iv)

    decrypted_text = decrypt_aes_cbc(ciphertext, secret_key, initialization_vector)
    print("DECRYPTED TEXT:", decrypted_text)
    result(decrypted_text)

def testing():
    skey = genkey()
    print_Key(skey)
    write_key_to_file(skey)

decrypt()
