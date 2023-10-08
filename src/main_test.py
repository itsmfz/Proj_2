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
# Print Key - This function is built to print the key 
# ----------------------------------------------------------------------------
def print_key(sk):
    if sk:
        print(f'Encryption Key:')
        hex_values = ' '.join([format(byte, '02X') for byte in sk])
        print(hex_values)

# ----------------------------------------------------------------------------
# Read plain text: This function is dedicated to only read the plaintext
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
# Encryption Block
# ----------------------------------------------------------------------------
def encrypt_block(block, key):
    key_hash = sha256(key).digest() #This line computes the SHA-256 hash of the encryption key (key) using Python's hashlib library. The .digest() method is called to obtain the binary representation of the hash.
    encrypted_block = bytes(x ^ y for x, y in zip(block, key_hash)) # This line performs the encryption operation. It iterates over each byte in the block and XORs it with the corresponding byte from the key_hash. This creates the encrypted block.
    return encrypted_block

# ----------------------------------------------------------------------------
# Pad : padding to a block of binary data to ensure that its length is a multiple of a specified block size
# ----------------------------------------------------------------------------
def pad_data(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

# ----------------------------------------------------------------------------
# Hex_data to file: This writes the hex data to the file
# ----------------------------------------------------------------------------
def write_data_to_hex_file(data, filename):
    hex_data = b64encode(data).decode('utf-8')
    with open(filename, 'w') as file:
        file.write(hex_data)

# ----------------------------------------------------------------------------
# Read Hex_data from file: This function is to read hex_data from file
# ----------------------------------------------------------------------------
def read_data_from_hex_file(filename):
    with open(filename, 'r') as file:
        hex_data = file.read()
    return b64decode(hex_data)

# ----------------------------------------------------------------------------
# Unpad : for removing padding from a block of binary data
# ----------------------------------------------------------------------------
def unpad_data(data):
    padding_length = data[-1]
    return data[:-padding_length]

# ----------------------------------------------------------------------------
# Decrypt - This block is to decrypt and follows the same approach as the Encrypt block
# ----------------------------------------------------------------------------
def decrypt_block(block, key):
    key_hash = sha256(key).digest()
    decrypted_block = bytes(x ^ y for x, y in zip(block, key_hash))
    return decrypted_block

# ----------------------------------------------------------------------------
# No code executed here; only module imports.
# ----------------------------------------------------------------------------
def write_to_result(decrypted_plaintext):
    result_file= 'data/result.txt'
    with open(result_file, 'w') as file:
        file.write(decrypted_plaintext)



ciphertext_file = 'data/ciphertext.txt'
iv_file = 'data/iv.txt'

def generate_random_iv():
    return os.urandom(16)

# ----------------------------------------------------------------------------
# AES Encryption: Function is used for AES encryption. It takes plaintext, a secret key, and an initialization vector (IV) as input and returns the ciphertext.
# ----------------------------------------------------------------------------
# Function to perform AES encryption in CBC (Cipher Block Chaining) mode
def encryption_aes(plaintext, key, iv):
    # Define the block size (AES block size is 16 bytes)
    block_size = 16
    
    # Pad the plaintext to match the block size
    plaintext = pad_data(plaintext.encode('utf-8'), block_size)
    
    # Initialize an empty ciphertext
    ciphertext = b''
    
    # Initialize the previous block with the IV (Initialization Vector)
    prev_block = iv

    # Iterate over the plaintext in blocks
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]  # Get the current block
        
        # XOR the current block with the previous ciphertext block or IV
        xor_block = bytes(x ^ y for x, y in zip(block, prev_block))
        
        # Encrypt the XORed block using the encryption key
        encrypted_block = encrypt_block(xor_block, key)
        
        # Append the encrypted block to the ciphertext
        ciphertext += encrypted_block
        
        # Update the previous block with the current encrypted block
        prev_block = encrypted_block

    # Return the final ciphertext
    return ciphertext


# ----------------------------------------------------------------------------
# Function to perform AES decryption in CBC (Cipher Block Chaining) mode
# ----------------------------------------------------------------------------

def decrypt_aes(ciphertext, key, iv):
    # Define the block size (AES block size is 16 bytes)
    block_size = 16
    
    # Initialize an empty plaintext
    plaintext = b''
    
    # Initialize the previous block with the IV (Initialization Vector)
    prev_block = iv

    # Iterate over the ciphertext in blocks
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]  # Get the current block
        
        # Decrypt the current block using the decryption key
        decrypted_block = decrypt_block(block, key)
        
        # XOR the decrypted block with the previous ciphertext block or IV
        plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_block))
        
        # Append the plaintext block to the overall plaintext
        plaintext += plaintext_block
        
        # Update the previous block with the current ciphertext block
        prev_block = block

    # Remove padding and decode the plaintext to UTF-8
    return unpad_data(plaintext).decode('utf-8')


# ----------------------------------------------------------------------------
# Function for Decoding
# ----------------------------------------------------------------------------
# Function to decrypt ciphertext and write the decrypted result
def Dec():
    # Read the encryption key from a file
    sk = read_key_from_file()
    write_key_to_file(sk)

    # Read the ciphertext and IV (Initialization Vector) from files
    c = read_data_from_hex_file(ciphertext_file)
    iv = read_data_from_hex_file(iv_file)

    # Decrypt the ciphertext using the encryption key and IV
    decrypted_plaintext = decrypt_aes(c, sk, iv)

    # Print the decrypted plaintext to the console
    print("DECRYPTED TEXT: ", decrypted_plaintext)

    # Write the decrypted plaintext to a result file
    write_to_result(decrypted_plaintext)


# ----------------------------------------------------------------------------
# Encode Function: This function is aimed at encoding
# ----------------------------------------------------------------------------
def Enc():
    sk = read_key_from_file()
    print_key(sk)

    f = read_plain_text()
    print("PLAIN TEXT: ", f)

    iv = generate_random_iv()
    print("RANDOM IV: ", iv)

    c = encryption_aes(f, sk, iv)
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
