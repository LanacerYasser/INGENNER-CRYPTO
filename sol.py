
import base64
import subprocess
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from base64 import b64decode
### variables to set
user = 'yasser' #if its not working just change it lenght , i think it worked with length = 3
PLAINTEXT = pad(b'user=yas&admin=0&authentificated=true',8) # yeah the username is yas (len = 3)
CIPHERTEXT = bytes.fromhex('60e008225b95db2be64b71eae82088dff1a159bed865f90e656aa40000d059132128853534e475e2') #CHANGE IT WITH YOUR ENC SESSION
BLOCK_SIZE = 8 # AES
PADDING_TYPE = "pkcs7"
OLD_STR = b"0" # string to flip
NEW_STR = b"1;" # string that will replace OLD_STR



if len(PLAINTEXT) != len(CIPHERTEXT):
    PLAINTEXT = pad(PLAINTEXT, block_size=BLOCK_SIZE, style=PADDING_TYPE)


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

# pos = same block offset ,in previous block
pos = (in_block - 1) * BLOCK_SIZE + block_offset
end_pos = pos + len(OLD_STR)

# here the magic happens...
result = CIPHERTEXT[:pos]

NEW_STR = b'1'
result+= strxor( strxor(OLD_STR,NEW_STR), CIPHERTEXT[pos:end_pos] )
result+= CIPHERTEXT[end_pos:]
print(F'HERE YOU GO : {result.hex()}')
