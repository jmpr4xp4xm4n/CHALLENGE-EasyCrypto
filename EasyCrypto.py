#!/usr/bin/python
 
import struct
import binascii
 
def mix(a, b):
        na = struct.unpack('<L', a)[0]
        nb = struct.unpack('<L', b)[0]
        return struct.pack('<L', na ^ nb)
 
def padData(data):
        padLength = 8 - (len(data) % 8)
        padLength = 8 if padLength == 0 else padLength
        result = struct.pack('<Q', padLength) + b'A'*padLength + data
        return result
 
def unpadData(data):
        padLength = struct.unpack_from('<Q', data)[0]
        if padLength > len(data):
                return None
        return data[8+padLength:]
 
def encryptBlock(block, blockKey):
        b = struct.unpack('<L', block)[0]
        k = struct.unpack('<L', blockKey)[0]
        encrypted = b * k
        return struct.pack('<Q', encrypted)
       
def decryptBlock(block, blockKey):
        b = struct.unpack('<Q', block)[0]
        k = struct.unpack('<L', blockKey)[0]
        decrypted = int(b / k)
        return struct.pack('<L', decrypted)
 
def encrypt(data, key):
        ciphertext = b''
        padded = padData(data)
        for i in range(0, len(padded), 4):
                ciphertext += encryptBlock(mix(padded[i:i+4], key), key)
        return ciphertext
 
def decrypt(ciphertext, key):
        data = b''
        for i in range(0, len(ciphertext), 8):
                data += mix(decryptBlock(ciphertext[i:i+8], key), key)
        unpadded = unpadData(data)
        return unpadded
       
# The ciphertext I want you to break is:
# c3b0f649b6316d0ae198a2e2b5316d0ab0df793009c4901254628acb6c7fb810620800dd68cebd12539b1b555eb8451262318d1eec623c0ecde120c418d217139046727483eff716909f7ae0bbefe312
# This should be possible without bruteforce. It will require some thinking!
 
# the data to encrypt
data = b"This is a test message.";
# the key to use (4 bytes, 32-bit)
key = b'\x13\x37\xCA\xFE'
encrypted = encrypt(data, key)
print("")
print("Encrypted:")
print(binascii.b2a_hex(encrypted).decode("ASCII"))
print("")
decrypted = decrypt(encrypted, key).decode("ASCII")
print("Decrypted: %s" % decrypted)
