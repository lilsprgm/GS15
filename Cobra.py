from operator import index
from sys import byteorder

import  numpy as np
import bitarray
import os
import random


#Step 1 add round key : Xor with a key the file 128 bits bloc/key
def split_binary_file(filename, chunk_size=16):  # 16 bytes = 128 bits
    """
    :param filename: The path to the binary file that needs to be split.
    :param chunk_size: The size of each chunk in bytes; defaults to 16 bytes.
    :return: A list of binary chunks read from the file, each with a maximum size of `chunk_size`.
    """
    chunks = []
    try:
        with open(filename, 'rb') as f:
            chunk = f.read(chunk_size)
            while chunk:
                chunks.append(bytearray(chunk))
                chunk = f.read(chunk_size)
    except FileNotFoundError:
        print(f"Error: The file {filename} does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    chunks[-1] += b'\x00' * (chunk_size - len(chunks[-1]))
    return chunks


def add_round_key(block, key):
    block ^= key
    return block



#Step 2 Substitution 32 fois Sbox 4 bits : 4 Sbox 0-7 8-16 ....

# Step 1: Create the S-Boxes as random permutations of values 0 to 15
def generate_sbox(size):
    sbox = list(range(size))  # Possible values for 4 bits (0 to 15)
    random.shuffle(sbox)    # Shuffle the values for a permutation
    return sbox




sbox1 = generate_sbox(16)
sbox2 = generate_sbox(16)
sbox3 = generate_sbox(16)
sbox4 = generate_sbox(16)
permut_matrix = generate_sbox(8)
sboxes = [sbox1, sbox2, sbox3, sbox4]



# Step 2: Substitution function
def apply_sbox(block):
    """
    Apply substitution using the 4 S-Boxes on a 128-bit block
    (represented here as a list of 32 four-bit values)
    """
    for i in range(16):
        sbox = sboxes[i // 4]       # Choose the S-Box based on the index (0-7, 8-15, 16-23, 24-31)
        left_part = (block & 0xF0)>>4
        right_part = block & 0x0F# Take the lower 4 bits of each element
        substituted_value_left = sbox[left_part]
        substituted_value_right = sbox[right_part]
        block = substituted_value_left<<4 | substituted_value_right

    return block

def inv_sbox(block):
    for i in range(16):
        sbox = sboxes[i // 4]       # Choose the S-Box based on the index (0-7, 8-15, 16-23, 24-31)
        left_part = (block[i] & 0xF0)>>4
        right_part = block[i] & 0x0F# Take the lower 4 bits of each element
        inv_value_left = sbox.index(left_part)
        inv_value_right = sbox.index(right_part)
        block[i] = inv_value_left<<4 | inv_value_right

    return block

#3

def feistel(block, key):
    left = []
    right = []
    for i in range(4): # on applique 4 rondes par itération
        left = block[0:8]
        right = block[8:16]
        tmp_left = left
        left = right
        right = tmp_left ^ F_function(key, right)

    block = concat_blocks([left, right], 64)
    return  block

def inv_feistel(block, key):
    left = []
    right = []
    for i in range(4):
        left = block[0:8]
        right = block[8:16]
        tmp_right = right
        right = left
        left = tmp_right ^ F_function(key, left)

    block = concat_blocks([left, right], 64)
    return block



def F_function(key, block):
    for i in range(len(block)):
        block[i] = inv_bits_order(block[i])
        block[i] = inv_mod257(block[i]+1)-1     # = (x+1)^-1 mod 257 -1
    block = permutation(block)
    # A faire étape 3 avec génération nb pseudo aléatoire et xor ???

    return block


def permutation(block):
    resultat = block
    for i in range(len(block)-1):
        resultat[i] = block[permut_matrix[i]]
    return resultat


def inv_mod257(x,mod = 257):
    """Calcule l'inverse multiplicatif de a modulo mod."""
    for i in range(mod):
        if (x * i) % mod == 1:
            return i
    return None  # Pas d'inverse multiplicatif si None

#Question : est ce qu'on utilise mod avec les entier ou dans GF256 avec le polynome x^8 +1

def inv_bits_order(byte):
    result = 0
    for i in range(8):
        result = (result << 1) | (byte & 1) #byte & 1 = LSB comme on décale premier LSB se trouve MSB a la fin
        byte >>= 1

    return result

def concat_blocks(input, blocksize):
    res = 0
    for block in input:
        res = res << blocksize
        res ^= block
    return res


# Pour toutes les fonction de décalage, la variable block size est en bit
def dec_circ_left(block, block_size, n):
    n = n%block_size
    rotated_block = (block << n) & ((1 << block_size) - 1) | (block >> (block_size - n)) # correspond a partie gauche | partie droite
    return rotated_block

def dec_circ_right(block, block_size, n):
    n = block_size - (n%block_size)
    rotated_block = (block << n) & ((1 << block_size) - 1) | (block >> (block_size - n))# correspond a partie gauche | partie droite
    print(bin(rotated_block))
    return rotated_block

def dec_lin_left(block, block_size, n):
    if n<block_size:
        rotated_block = (block << n) & ((1 << block_size) - 1)
        return rotated_block
    else:
        return 0


def trans_lineaire(block):

    a=int.from_bytes(block[0:4], byteorder='big')
    b=int.from_bytes(block[4:8], byteorder='big')
    c=int.from_bytes(block[8:12], byteorder='big')
    d=int.from_bytes(block[12:], byteorder='big')

    a = dec_circ_left(a, 32, 13)
    c= dec_circ_left(c, 32, 3)
    b = a ^ b ^ c
    d = d ^ c ^ dec_lin_left(a, 32, 3)
    b = dec_circ_left(b, 32, 1)
    d = dec_circ_left(d, 32, 7)
    a = a^b^d
    c = c ^ d ^ dec_lin_left(b, 32, 7)
    a = dec_circ_left(a, 32, 5)
    c = dec_circ_left(c, 32, 22)

    res = (a.to_bytes(4, byteorder='big') + b.to_bytes(4, byteorder='big')# pb c'est pas + mais concat je pense
           +c.to_bytes(4, byteorder='big') +d.to_bytes(4, byteorder='big'))

    return res


def inv_trans_lineaire(block):
    a = int.from_bytes(block[0:4], byteorder='big')
    b = int.from_bytes(block[4:8], byteorder='big')
    c = int.from_bytes(block[8:12], byteorder='big')
    d = int.from_bytes(block[12:], byteorder='big')

    c = dec_circ_right(c, 32, 22)
    a = dec_circ_right(a, 32, 5)
    c = c ^ d ^ dec_lin_left(b, 32, 7)
    a = a ^ b ^ d
    b = dec_circ_right(b, 32, 1)
    d = dec_circ_right(d, 32, 7)
    d = d ^ c ^ dec_lin_left(a, 32, 3)
    b = a ^ b ^ c
    a = dec_circ_right(a, 32, 13)
    c = dec_circ_right(c, 32, 3)

    res = a.to_bytes(4, byteorder='big') + b.to_bytes(4, byteorder='big') + c.to_bytes(4,
                                                                                       byteorder='big') + d.to_bytes(
        4, byteorder='big')

    return res


def key_scheduling(key):
    # key sous forme bytearray -> 32*8 = 256 bits
    tab_box = []
    phi = 0x16180339  # Constante binaire de longueur 4 octets
    key += b'\x00' * (32 - len(key))  # Compléter avec des 0 pour obtenir 32 octets

    # Extraction des premiers 8 blocs de 4 octets (32 bits)
    for i in range(0, 8):
        tab_box.append(int.from_bytes(key[i * 4:i * 4 + 4], byteorder='big'))

    # Génération des 124 autres clés
    for i in range(8, 132):
        tmp = (tab_box[i - 8] ^ tab_box[i - 5] ^ tab_box[i - 3] ^ tab_box[i - 1] ^ phi ^ i)
        tmp = dec_circ_left(tmp, 32, 11)  # Décalage circulaire à gauche
        tab_box.append(tmp)


    #Concatenation 4 blocs puis application des sbox
    tab_key = []
    for i in range (0, len(tab_key)):
        tab_key.append(concat_blocks(tab_key[i:i+4],32))
        i+=4

    for i in range(0, len(tab_key)):
        tab_key[i] = apply_sbox(tab_key[i])
        
    return tab_key

def sym_encryption_cobra(file_name, key, nb_round):
    file = split_binary_file(file_name)
    tab_key = key_scheduling(key)
    for i in range(0, nb_round):
        for j in range (0, len(file)):
            file[j] = add_round_key(file[j], tab_key[i])
            file[j] = apply_sbox(file[j])
            file[j] = feistel(file[j], key)
            file[j] = trans_lineaire(file[j])

    return file




def sym_decryption_cobra(file_name, key, nb_round):
    file = split_binary_file(file_name)
    tab_key = key_scheduling(key)
    for i in range(0, nb_round):
        for j in range (0, len(file)):
            file[j] = inv_trans_lineaire(file[j])
            file[j] = inv_feistel(file[j], tab_key[nb_round-i-1])
            file[j] = inv_sbox(file[j])
            file[j] = add_round_key(file[j], tab_key[nb_round-i-1])

    return file

