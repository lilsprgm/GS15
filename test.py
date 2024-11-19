import random

x = 1


y = x.to_bytes()
print(y)

tab = bytes([0xff, 0x05])

tab[0] = tab[0]& 0b01000000

print(tab)

