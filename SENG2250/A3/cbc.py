import hashlib
from Crypto.Cipher import AES
import secrets


def encrypt(plaintext, key, nonce):
    # Initialise encryption object and turn nonce to 16 bytes. nonce will initially be secrets.token_urlsafe(16) (str) and will be converted to bytes
    ciphertext = []
    aes = AES.new(key, AES.MODE_ECB)
    nonce = (
        int("0x" + hashlib.sha256(str(nonce).encode()).hexdigest(), 16) % 2**128
    ).to_bytes(16, "big")

    # Transform plaintext to bytes and then split it into blocks of 16 bytes
    plaintext = str(plaintext).encode()
    plaintext_blocks = [plaintext[i : i + 16] for i in range(0, len(plaintext), 16)]

    # Initiate CBC encryption mode
    for block in plaintext_blocks:
        # XOR the block with the nonce
        block = bytewiseXOR(block, nonce)
        # Encrypt the block
        block = aes.encrypt(block)
        # Append the ciphertext to the list after converting it to hex
        ciphertext.append(block.hex())
        # Set the nonce to the ciphertext
        nonce = block

    # Return parsed ciphertext as a string of hex numbers
    return "".join([c for c in ciphertext])


def decrypt(ciphertext, key, nonce):
    # Initialise decryption object and turn nonce to 16 bytes. nonce will initially be secrets.token_urlsafe(16) (str) and will be converted to bytes
    plaintext = []
    aes = AES.new(key, AES.MODE_ECB)
    nonce = (
        int("0x" + hashlib.sha256(str(nonce).encode()).hexdigest(), 16) % 2**128
    ).to_bytes(16, "big")

    # Split ciphertext to blocks again, this time by increments of 32 so we get our four blocks back
    ciphertext_blocks = [ciphertext[i : i + 32] for i in range(0, len(ciphertext), 32)]

    # Initiate CBC decryption mode
    for block in ciphertext_blocks:
        # Each ciphertext block is in string form, without the 0x. We need to convert it back to bytes
        block = int("0x" + block, 16).to_bytes(16, "big")
        # Decrypt the current block, xor it with the nonce and append it to the plaintext list
        plaintext_block = aes.decrypt(block)
        plaintext_block = bytewiseXOR(plaintext_block, nonce)
        plaintext.append(plaintext_block)
        # Set the next nonce as the current block
        nonce = block

    # Return parsed plaintext
    return "".join([p.decode() for p in plaintext])


def hashed_mac(message, key):
    # Initialise padding constants
    opad = int("0x" + "5c" * len(key), 16).to_bytes(len(key), "big")
    ipad = int("0x" + "36" * len(key), 16).to_bytes(len(key), "big")

    # Follow the formula
    key_xor_opad = bytewiseXOR(key, opad)
    key_xor_ipad = bytewiseXOR(key, ipad)

    # Concatenate message and key_xor_ipad then hash the result
    key_xor_ipad_message = key_xor_ipad + message.encode()
    hashed_key_xor_ipad_message = hashlib.sha256(key_xor_ipad_message).digest()

    # Concatenate hashed_key_xor_ipad_message and key_xor_opad then hash the result
    concat = key_xor_opad + hashed_key_xor_ipad_message

    # Return the hexdigest of the hash
    return hashlib.sha256(concat).hexdigest()


def bytewiseXOR(a, b):
    # Zip the two byte arrays together, tuple unpack each pair, XOR them and convert back to bytes
    return bytes([x ^ y for x, y in zip(a, b)])
