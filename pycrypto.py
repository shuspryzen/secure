from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Key and Initialization Vector (IV) must be 16, 24, or 32 bytes for AES
key = get_random_bytes(16)  # 16-byte key (128-bit)
iv = get_random_bytes(16)   # 16-byte IV

def encrypt(plain_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher in CBC mode
    padded_text = pad(plain_text.encode(), AES.block_size)  # Pad the plaintext
    encrypted = cipher.encrypt(padded_text)  # Encrypt the data
    return encrypted

def decrypt(encrypted_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher in CBC mode
    decrypted = cipher.decrypt(encrypted_text)  # Decrypt the data
    return unpad(decrypted, AES.block_size).decode()  # Remove padding and decode

# Example usage
plain_text = input("enter the message:")
print(f"Original: {plain_text}")

# Encrypt the message
encrypted = encrypt(plain_text, key, iv)
print(f"Encrypted: {encrypted.hex()}")

# Decrypt the message
decrypted = decrypt(encrypted, key, iv)
print(f"Decrypted: {decrypted}")
