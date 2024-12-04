import random
# Définir une variable contenant un seul octet (8 bits)
x = 0x1
y = 0x01

res= (x<<8) | y

print(res.to_bytes(2, byteorder='big'))