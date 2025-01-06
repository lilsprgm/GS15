import random

# S-boxes générées à partir de la fonction générate sbox
sbox1 = [5, 14, 7, 3, 8, 11, 9, 0, 6, 15, 1, 4, 13, 2, 10, 12]
sbox2 = [0, 15, 5, 12, 11, 9, 14, 7, 3, 8, 4, 10, 1, 6, 13, 2]
sbox3 = [11, 15, 2, 7, 10, 3, 8, 13, 6, 14, 9, 12, 0, 1, 5, 4]
sbox4 = [9, 14, 10, 6, 13, 12, 3, 15, 7, 0, 5, 2, 4, 11, 8, 1]
permut_matrix = [5, 3, 7, 4, 6, 1, 0, 2]
sboxes = [sbox1, sbox2, sbox3, sbox4]

def split_binary_file(filename, chunk_size=16):  # 16 bytes = 128 bits
    """
    Divise un fichier binaire en blocs de taille chunk_size.

    :param filename: Le chemin vers le fichier binaire à diviser.
    :param chunk_size: La taille de chaque bloc en octets; par défaut 16 octets.
    :return: Une liste de blocs binaires lus depuis le fichier, chacun de taille maximale chunk_size.
    """
    chunks = []
    try:
        with open(filename, 'rb') as f:
            chunk = f.read(chunk_size)
            while chunk:
                chunks.append(bytearray(chunk))
                chunk = f.read(chunk_size)
    except FileNotFoundError:
        print(f"Erreur: Le fichier {filename} n'existe pas.")
    except Exception as e:
        print(f"Une erreur inattendue s'est produite: {e}")

    # Ajouter des zéros pour compléter le dernier bloc si nécessaire
    chunks[-1] += b'\x00' * (chunk_size - len(chunks[-1]))
    return chunks

def add_round_key(block, key):
    """
    Ajoute une clé de tour à un bloc en utilisant l'opération XOR.

    :param block: Le bloc de données à chiffrer.
    :param key: La clé de tour.
    :return: Le bloc après ajout de la clé de tour.
    """
    for i in range(len(block)):
        block[i] ^= key[i]
    return block

def generate_sbox(size):
    """
    Génère une S-box comme une permutation aléatoire des valeurs de 0 à size-1.

    :param size: La taille de la S-box.
    :return: Une S-box générée aléatoirement.
    """
    sbox = list(range(size))  # Valeurs possibles pour 4 bits (0 à 15)
    random.shuffle(sbox)  # Mélanger les valeurs pour obtenir une permutation
    print(sbox)
    return sbox

def apply_sbox(block):
    """
    Applique une substitution en utilisant les 4 S-boxes sur un bloc de 128 bits.

    :param block: Le bloc de données à substituer.
    :return: Le bloc après substitution.
    """
    for i in range(len(block)):
        sbox = sboxes[i // 4]  # Choisir la S-box en fonction de l'index (0-7, 8-15, 16-23, 24-31)
        left_part = (block[i] & 0xF0) >> 4
        right_part = block[i] & 0x0F  # Prendre les 4 bits de poids faible de chaque élément
        substituted_value_left = sbox[left_part]
        substituted_value_right = sbox[right_part]
        block[i] = substituted_value_left << 4 | substituted_value_right
    return block

def inv_sbox(block):
    """
    Applique l'inverse de la substitution en utilisant les 4 S-boxes sur un bloc de 128 bits.

    :param block: Le bloc de données à substituer.
    :return: Le bloc après substitution inverse.
    """
    for i in range(16):
        sbox = sboxes[i // 4]  # Choisir la S-box en fonction de l'index (0-7, 8-15, 16-23, 24-31)
        left_part = (block[i] & 0xF0) >> 4
        right_part = block[i] & 0x0F  # Prendre les 4 bits de poids faible de chaque élément
        inv_value_left = sbox.index(left_part)
        inv_value_right = sbox.index(right_part)
        block[i] = inv_value_left << 4 | inv_value_right
    return block

def feistel(block, key):
    """
    Applique la structure de Feistel sur un bloc de données.

    :param block: Le bloc de données à chiffrer.
    :param key: La clé de chiffrement.
    :return: Le bloc après application de la structure de Feistel.
    """
    left = int.from_bytes(block[0:8],byteorder='big')
    right = int.from_bytes(block[8:16],byteorder='big')
    for i in range(4):  # On applique 4 rondes par itération
        tmp_left = left
        left = right
        right = tmp_left ^ F_function(key, right)
    block = concat_blocks([left, right], 64)
    return bytearray(block.to_bytes(16, byteorder='big'))

def inv_feistel(block, key):
    """
    Applique l'inverse de la structure de Feistel sur un bloc de données.

    :param block: Le bloc de données à déchiffrer.
    :param key: La clé de déchiffrement.
    :return: Le bloc après application de l'inverse de la structure de Feistel.
    """
    left = int.from_bytes(block[0:8],byteorder='big')
    right = int.from_bytes(block[8:16],byteorder='big')
    for i in range(4):
        tmp_right = right
        right = left
        left = tmp_right ^ F_function(key, left)
    block = concat_blocks([left, right], 64)
    return bytearray(block.to_bytes(16, byteorder='big'))

def F_function(key, block):
    """
    Fonction F utilisée dans la structure de Feistel.

    :param key: La clé de chiffrement.
    :param block: Le bloc de données à transformer.
    :return: Le bloc après application de la fonction F.
    """
    block = bytearray(block.to_bytes(8, byteorder='big'))
    for i in range(len(block)):
        block[i] = inv_bits_order(block[i])
        block[i] = inv_mod257(block[i] + 1) - 1  # = (x+1)^-1 mod 257 -1
    block = permutation(block)
    return int.from_bytes(block,byteorder='big')

def permutation(block):
    """
    Applique une permutation sur un bloc de données.

    :param block: Le bloc de données à permuter.
    :return: Le bloc après permutation.
    """
    resultat = block
    for i in range(len(block) - 1):
        resultat[i] = block[permut_matrix[i]]
    return resultat

def inv_mod257(x, mod=257):
    """
    Calcule l'inverse multiplicatif de x modulo mod.

    :param x: L'entier dont on veut l'inverse.
    :param mod: Le modulo.
    :return: L'inverse multiplicatif de x modulo mod.
    """
    for i in range(mod):
        if (x * i) % mod == 1:
            return i
    return None  # Pas d'inverse multiplicatif si None

def inv_bits_order(byte):
    """
    Inverse l'ordre des bits d'un octet.

    :param byte: L'octet dont on veut inverser l'ordre des bits.
    :return: L'octet avec l'ordre des bits inversé.
    """
    result = 0
    for i in range(8):
        result = (result << 1) | (byte & 1)  # byte & 1 = LSB, comme on décale, le premier LSB se trouve MSB à la fin
        byte >>= 1
    return result

def concat_blocks(input, blocksize):
    """
    Concatène plusieurs blocs en un seul entier.

    :param input: La liste des blocs à concaténer.
    :param blocksize: La taille de chaque bloc en bits.
    :return: Le résultat de la concaténation.
    """
    res = 0
    for block in input:
        res = res << blocksize
        res ^= block
    return res

def dec_circ_left(block, block_size, n):
    """
    Effectue un décalage circulaire à gauche sur un bloc de données.

    :param block: Le bloc de données à décaler.
    :param block_size: La taille du bloc en bits.
    :param n: Le nombre de bits à décaler.
    :return: Le bloc après décalage circulaire à gauche.
    """
    n = n % block_size
    rotated_block = (block << n) & ((1 << block_size) - 1) | (block >> (block_size - n))  # correspond à partie gauche | partie droite
    return rotated_block

def dec_circ_right(block, block_size, n):
    """
    Effectue un décalage circulaire à droite sur un bloc de données.

    :param block: Le bloc de données à décaler.
    :param block_size: La taille du bloc en bits.
    :param n: Le nombre de bits à décaler.
    :return: Le bloc après décalage circulaire à droite.
    """
    n = block_size - (n % block_size)
    rotated_block = (block << n) & ((1 << block_size) - 1) | (block >> (block_size - n))  # correspond à partie gauche | partie droite
    return rotated_block

def dec_lin_left(block, block_size, n):
    """
    Effectue un décalage linéaire à gauche sur un bloc de données.

    :param block: Le bloc de données à décaler.
    :param block_size: La taille du bloc en bits.
    :param n: Le nombre de bits à décaler.
    :return: Le bloc après décalage linéaire à gauche.
    """
    if n < block_size:
        rotated_block = (block << n) & ((1 << block_size) - 1)
        return rotated_block
    else:
        return 0

def trans_lineaire(block):
    """
    Applique une transformation linéaire sur un bloc de données.

    :param block: Le bloc de données à transformer.
    :return: Le bloc après transformation linéaire.
    """
    a = int.from_bytes(block[0:4], byteorder='big')
    b = int.from_bytes(block[4:8], byteorder='big')
    c = int.from_bytes(block[8:12], byteorder='big')
    d = int.from_bytes(block[12:], byteorder='big')

    a = dec_circ_left(a, 32, 13)
    c = dec_circ_left(c, 32, 3)
    b = a ^ b ^ c
    d = d ^ c ^ dec_lin_left(a, 32, 3)
    b = dec_circ_left(b, 32, 1)
    d = dec_circ_left(d, 32, 7)
    a = a ^ b ^ d
    c = c ^ d ^ dec_lin_left(b, 32, 7)
    a = dec_circ_left(a, 32, 5)
    c = dec_circ_left(c, 32, 22)

    res = (a.to_bytes(4, byteorder='big') + b.to_bytes(4, byteorder='big')
           + c.to_bytes(4, byteorder='big') + d.to_bytes(4, byteorder='big'))

    return bytearray(res)

def inv_trans_lineaire(block):
    """
    Applique l'inverse de la transformation linéaire sur un bloc de données.

    :param block: Le bloc de données à transformer.
    :return: Le bloc après transformation linéaire inverse.
    """
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

    res = a.to_bytes(4, byteorder='big') + b.to_bytes(4, byteorder='big') + c.to_bytes(4, byteorder='big') + d.to_bytes(4, byteorder='big')

    return bytearray(res)

def key_scheduling(key):
    """
    Génère les sous-clés pour chaque tour de chiffrement.

    :param key: La clé principale.
    :return: La liste des sous-clés générées.
    """
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

    # Concaténation de 4 blocs puis application des S-boxes
    tab_key = []
    for i in range(0, len(tab_box), 4):
        tab_key.append(bytearray(concat_blocks(tab_box[i:i + 4], 32).to_bytes(16, byteorder='big')))

    for i in range(0, len(tab_key)):
        tab_key[i] = apply_sbox(tab_key[i])

    return tab_key

def sym_encryption_cobra(file_name, key, nb_round):
    """
    Chiffre un fichier en utilisant l'algorithme COBRA.

    :param file_name: Le nom du fichier à chiffrer.
    :param key: La clé de chiffrement.
    :param nb_round: Le nombre de tours de chiffrement.
    """
    data = split_binary_file(file_name)
    tab_key = key_scheduling(key)
    for i in range(0, nb_round):
        for j in range(0, len(data)):
            data[j] = add_round_key(data[j], tab_key[i])
            data[j] = apply_sbox(data[j])
            data[j] = feistel(data[j], key)
            data[j] = trans_lineaire(data[j])

    with open(file_name, 'wb') as file:
        for i in range(0, len(data)):
            file.write(data[i])

def sym_decryption_cobra(file_name, key, nb_round):
    """
    Déchiffre un fichier en utilisant l'algorithme COBRA.

    :param file_name: Le nom du fichier à déchiffrer.
    :param key: La clé de déchiffrement.
    :param nb_round: Le nombre de tours de déchiffrement.
    """
    data = split_binary_file(file_name)
    tab_key = key_scheduling(key)
    for i in range(0, nb_round):
        for j in range(0, len(data)):
            data[j] = inv_trans_lineaire(data[j])
            data[j] = inv_feistel(data[j], tab_key[nb_round - i - 1])
            data[j] = inv_sbox(data[j])
            data[j] = add_round_key(data[j], tab_key[nb_round - i - 1])

    with open(file_name, 'wb') as file:
        for i in range(0, len(data)):
            file.write(data[i])
