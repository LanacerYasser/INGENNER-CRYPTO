
import base64
import subprocess
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from base64 import b64decode
### variables to set
user = 'yasser' #if its not working just change it lenght , i think it worked with length = 3
PLAINTEXT = pad(b'user=yas&admin=0&authentificated=true',8) # yeah the username is yas (len = 3)
print(len(PLAINTEXT))
CIPHERTEXT = bytes.fromhex('60e008225b95db2be64b71eae82088dff1a159bed865f90e656aa40000d059132128853534e475e2') #the enc session , its variable , change it
print(len(CIPHERTEXT))
BLOCK_SIZE = 8 
PADDING_TYPE = "pkcs7"
OLD_STR = b"0" # string to flip
NEW_STR = b"1;" # string that will replace OLD_STR


xxd_cmd = ["xxd", "-g1", "-c", str(BLOCK_SIZE)]

print("\n[+] Infos:")
print("OLD_STR = %s" % OLD_STR)
print("NEW_STR = %s" % NEW_STR)

print("\n[+] Plaintext (%d bytes):" % len(PLAINTEXT))
subprocess.run(xxd_cmd, input=PLAINTEXT)

if len(PLAINTEXT) != len(CIPHERTEXT):
    PLAINTEXT = pad(PLAINTEXT, block_size=BLOCK_SIZE, style=PADDING_TYPE)

print("\n[+] Plaintext [Padded with %s] (%d bytes):" % (PADDING_TYPE, len(PLAINTEXT)))
subprocess.run(xxd_cmd, input=PLAINTEXT)

print("\n[+] Ciphertext (%d bytes):" % len(CIPHERTEXT))
subprocess.run(xxd_cmd, input=CIPHERTEXT)

assert len(CIPHERTEXT) % BLOCK_SIZE == 0
assert OLD_STR in PLAINTEXT

blocks = [PLAINTEXT[i:i + BLOCK_SIZE] for i in
        range(0, len(PLAINTEXT), BLOCK_SIZE)]
block_offset = 0
in_block = -1
for block_id, block in enumerate(blocks):
    if OLD_STR in block:
        in_block = block_id
        block_offset = block.find(OLD_STR)
        break
if in_block == -1:
    raise Exception("String to flip must be contained in one single block")
elif in_block == 0:
    raise Exception("String to flip cannot be part of the first block")

# pos = same block offset ,in previous block
pos = (in_block - 1) * BLOCK_SIZE + block_offset
end_pos = pos + len(OLD_STR)

# here the magic happens...
result = CIPHERTEXT[:pos]

print(OLD_STR)
NEW_STR = b'1'
result+= strxor( strxor(OLD_STR,NEW_STR), CIPHERTEXT[pos:end_pos] )
result+= CIPHERTEXT[end_pos:]

print("\033[32m\n[+] Flipped ciphertext:")
subprocess.run(xxd_cmd, input=result)
print("\n[+] Flipped ciphertext [BASE64]:")
print(base64.b64encode(result).decode() + "\033[0m")


a = b64decode('YOAIIluV2yrmS3Hq6CCI3/GhWb7YZfkOZWqkAADQWRMhKIU1NOR14g==') # it depends on the enc session , its variable , change it

print(a.hex()) #the session to give