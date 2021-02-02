import os
import base64
import getpass
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encryption():
    # First, we grab the contents of stdin and make sure it's a single string
    plaintext = "".join( sys.stdin.readlines() ).encode('utf-8')

    # Use getpass to prompt the user for a password
    password = getpass.getpass()
    password2 = getpass.getpass("Enter password again:")

    # Do a quick check to make sure that the password is the same!
    if password != password2:
        sys.stderr.write("Passwords did not match")
        sys.exit()

    ### START: This is what you have to change

    # We generate a random salt and iv 
    salt = os.urandom(16)
    iv = os.urandom(16)   

    # The key for our symmetric system will be from PBKDF2 with 100,000
    kdf  = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000)
    key = kdf.derive(password.encode('utf-8'))

    # PKCS7 Padding so that plaintext is a multiple of block size of AES
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()

    # Dividing the key into 128 bits each, so that it can fed into AES-128 and HMAC respectively
    AES_Key = key[:16]
    HMAC_Key = key[16:]

    # Encrpytion with AES-128 in CBC mdode
    cipher = Cipher(algorithms.AES(AES_Key), modes.CBC(iv))
    encrpytor = cipher.encryptor()
    ciphertext = encrpytor.update(padded_data) + encrpytor.finalize()

    # HMAC to provide integrity by using Encrypt, then MAC

    h = hmac.HMAC(HMAC_Key, hashes.SHA256())
    h.update(ciphertext)
    ct_hmac = ciphertext + h.finalize() + iv + salt
    # Return the ciphertext to standard out
    sys.stdout.write(base64.urlsafe_b64encode(ct_hmac).decode('utf-8'))

    ### END: This is what you have to change

def decryption():
    # Grab stdin.
    stdin_contents = "".join( sys.stdin.readlines() )
    
    # Cinvert to bytes for the ciphertext
    ciphertext = base64.urlsafe_b64decode(stdin_contents.encode('utf-8'))
    
    ### START: This is what you have to change

    salt = ciphertext[-16:]
    iv = ciphertext[-32: -16]
    og_ciphertext = ciphertext[:-32]
    # Derive the key in the same way we did in encryption
    password = getpass.getpass()

    # The key for our symmetric system will be from PBKDF2 with 100,000
    kdf  = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000)
    key = kdf.derive(password.encode('utf-8'))


    AES_Key = key[:16]
    HMAC_Key = key[16:]

    # To Verify the authenticity, we verify the signature
    h = hmac.HMAC(HMAC_Key, hashes.SHA256())
    h.update(og_ciphertext[:-32])
    try:
        h.verify(og_ciphertext[-32:])
    except:
        sys.stderr.write("Decryption failed. Incorrect MAC.\n")

    # Attempt to decrypt.
    try:
        og_ciphertext = og_ciphertext[:-32]
        cipher = Cipher(algorithms.AES(AES_Key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(og_ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize() 
    except:
        sys.stderr.write("Decryption failed. Check your password or the file.\n")
        sys.exit()

    # Return the plaintext to stdout
    sys.stdout.write(plaintext.decode('utf-8'))

    ### END: This is what you have to change

try:
    mode = sys.argv[1]
    assert( mode in ['-e', '-d'] )
except:
    sys.stderr.write("Unrecognized mode. Usage:\n")
    sys.stderr.write("'python3 fernet.py -e' encrypts stdin and returns the ciphertext to stdout\n")
    sys.stderr.write("'python3 fernet.py -d' decrypts stdin and returns the plaintext to stdout\n")

if mode == '-e':
    encryption()
elif mode == '-d':
    decryption()
