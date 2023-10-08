# Import necessary modules
import os            # Operating system-related functions
import secrets       # Cryptographically strong random number generation
from hashlib import sha256  # Hash function for secure hashing
from base64 import b64encode, b64decode  # Encoding/decoding data in base64 format

# ----------------------------------------------------------------------------
# Generate Key Function: This function is to generate a random 256 bit encryptioon key
# ----------------------------------------------------------------------------
def generate_key():
    #Generates a random 256-bit encryption key.
    #bytes: A 256-bit (32-byte) random encryption key.
    encryption_key = secrets.token_bytes(32) # Generate a 32-byte random key
    return encryption_key

# ----------------------------------------------------------------------------
# Write key to file: This writes to the key.txt file
# ----------------------------------------------------------------------------
def write_key_to_file(key, filename='data/key.txt'):
    #Writes an encryption key to a text file in hexadecimal format.
    #key (bytes): The encryption key to be written.
    #filename : The name of the file to write the key to. Default is 'data/key.txt'.
    hex_key = key.hex()
    with open(filename, 'w') as file:
        file.write(hex_key)

# ----------------------------------------------------------------------------
# Read key from file: This reads the key from the key.txt file.
# ----------------------------------------------------------------------------
def read_key_from_file(filename='data/key.txt'):
    #Reads an encryption key from a text file in hexadecimal format

    try:
        with open(filename, 'r') as file:
            hex_key = file.read().strip()
            key = bytes.fromhex(hex_key)
        return key
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        return None
    
# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def generate_random_key():
    key = secrets.token_bytes(32)
    return key

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def print_key(sk):
    if sk:
        print(f'Encryption Key:')
        hex_values = ' '.join([format(byte, '02X') for byte in sk])
        print(hex_values)

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def read_plain_text(filename='data/plaintext.txt'):
    try:
        with open(filename, 'r') as file:
            text = file.read()
        return text
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        return None

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def encrypt_block(block, key):
    key_hash = sha256(key).digest()
    encrypted_block = bytes(x ^ y for x, y in zip(block, key_hash))
    return encrypted_block

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def pad_data(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def write_data_to_hex_file(data, filename):
    hex_data = b64encode(data).decode('utf-8')
    with open(filename, 'w') as file:
        file.write(hex_data)

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def read_data_from_hex_file(filename):
    with open(filename, 'r') as file:
        hex_data = file.read()
    return b64decode(hex_data)

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def unpad_data(data):
    padding_length = data[-1]
    return data[:-padding_length]

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def decrypt_block(block, key):
    key_hash = sha256(key).digest()
    decrypted_block = bytes(x ^ y for x, y in zip(block, key_hash))
    return decrypted_block

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def save_decrypted_result(decrypted_data):
    result_file = 'data/decrypted_result.txt'
    with open(result_file, 'w') as file:
        file.write(decrypted_data)

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def write_to_result(decrypted_plaintext):
    result_file= 'data/result.txt'
    with open(result_file, 'w') as file:
        file.write(decrypted_plaintext)

# Functions from the second code
ciphertext_file = 'data/ciphertext.txt'
iv_file = 'data/iv.txt'

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def generate_random_iv():
    return os.urandom(16)

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def encrypt_aes_cbc(plaintext, key, iv):
    block_size = 16
    plaintext = pad_data(plaintext.encode('utf-8'), block_size)
    ciphertext = b''
    prev_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        xor_block = bytes(x ^ y for x, y in zip(block, prev_block))
        encrypted_block = encrypt_block(xor_block, key)
        ciphertext += encrypted_block
        prev_block = encrypted_block

    return ciphertext

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def decrypt_aes_cbc(ciphertext, key, iv):
    block_size = 16
    plaintext = b''
    prev_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        decrypted_block = decrypt_block(block, key)
        plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_block))
        plaintext += plaintext_block
        prev_block = block

    return unpad_data(plaintext).decode('utf-8')

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def Dec():
    sk = read_key_from_file()
    print("SECRET KEY READ")
    write_key_to_file(sk)

    c = read_data_from_hex_file(ciphertext_file)
    iv = read_data_from_hex_file(iv_file)

    decrypted_plaintext = decrypt_aes_cbc(c, sk, iv)
    print("DECRYPTED TEXT: ", decrypted_plaintext)
    write_to_result(decrypted_plaintext)

# ----------------------------------------------------------------------------
# Encode Function: This function is aimed at encoding
# ----------------------------------------------------------------------------
def Enc():
    sk = read_key_from_file()
    print("SECRET KEY READ")
    print_key(sk)

    f = read_plain_text()
    print("PLAIN TEXT: ", f)

    iv = generate_random_iv()
    print("RANDOM IV: ", iv)

    c = encrypt_aes_cbc(f, sk, iv)
    print("CIPHERTEXT: ", c)

    write_data_to_hex_file(c, ciphertext_file)
    write_data_to_hex_file(iv, iv_file)

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# genKeys: This function is aimed to generate the keys using the generate_key fuction after which we utilize the print_key and write_key_to_file function to print and write the key to the file respectively
# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def genKeys():
    sk = generate_key()
    print_key(sk)
    write_key_to_file(sk)

# --------------------------------------------------------------------------------------------------------------------------------------------------------
# Main function, in this function you will see the call of the 'Key-Generation' function, the Encoding function and the Decoding function
# --------------------------------------------------------------------------------------------------------------------------------------------------------
def main():
    genKeys()
    Enc()
    Dec()

# --------------------------------------------------------------------------------------------------------------------------------------------------------
# This calls the main function in order to run the code
# --------------------------------------------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
