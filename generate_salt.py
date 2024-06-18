import os
import base64

# Generate a 16-byte (128-bit) random salt
salt = os.urandom(16)

# Encode the salt in a way that it can be easily stored and retrieved (e.g., base64)
encoded_salt = base64.b64encode(salt).decode('utf-8')

print(f"Generated Salt: {encoded_salt}")