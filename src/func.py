import secrets
from hashlib import sha256
from base64 import b64encode, b64decode

def genkey():
    key = secrets.token_bytes(32)
    return key

def write_key_to_file(key, filename='data/key.txt'):
    # Convert the bytes key to a hexadecimal string
    hex_key = key.hex()
    print(hex_key)

    # Open the file and write the hexadecimal key
    with open(filename, 'w') as file:
        file.write(hex_key)

def print_Key(sk):
    # Convert the bytes key to a hexadecimal string
    sk_hex = sk.hex()

    # Format and print the key as a hexadecimal string
    print(f'Key: {" ".join(format(byte, "02X") for byte in bytes.fromhex(sk_hex))}')



def write_to_file(file_path, text_to_write):
    try:
        with open(file_path, 'w') as file:
            file.write(text_to_write)
        print(f"Text has been successfully written to '{file_path}'.")
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' could not be found.")

def read_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            file_contents = file.read()
        return file_contents
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' could not be found.")
        return None

def write_hex_data_to_file(file_path, hex_data):
    with open(file_path, 'w') as file:
        file.write(hex_data)
    print(f"Hexadecimal data has been successfully written to '{file_path}'.")

def read_hex_data_from_file(file_path):
    with open(file_path, 'r') as file:
        hex_data = file.read()
    return hex_data

def unpad(plaintext):
    return plaintext[:-plaintext[-1]]

def pad(plaintext, block_size):
    return plaintext.ljust(len(plaintext) + block_size - len(plaintext) % block_size, bytes([block_size - len(plaintext) % block_size]))

def read_plain_text(filename='data/plaintext.txt'):
    with open(filename, 'r') as file:
        text = file.read()
    return text

def aes_encrypt_block(block, key):
    key_hash = sha256(key).digest()
    encrypted_block = bytes(
        (x ^ y ^ (x & y))
        for x, y in zip(block, key_hash)
    )
    return encrypted_block

def aes_decrypt_block(block, key):
    key_hash = sha256(key).digest()
    decrypted_block = bytes(
        (x ^ y ^ (x | y))
        for x, y in zip(block, key_hash)
    )
    return decrypted_block

def result(decrypted_plaintext):
    result_file = 'data/result.txt'
    with open(result_file, 'w') as file:
        file.write(decrypted_plaintext)

tt = genkey()
print(tt)
print_Key(tt)
    