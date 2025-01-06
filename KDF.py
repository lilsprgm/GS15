import numpy as np

# Constantes de tours pour Keccak
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Décalages de rotation pour Keccak
ROTA_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]

def test_input():
    """
    Fonction pour tester l'entrée utilisateur.

    :return: Le mot de passe entré par l'utilisateur.
    """
    mdp = input('Entrer mdp')
    return mdp

def bytes_to_bits(data):
    """
    Convertit un bytearray en bits sous forme d'une liste.

    :param data: Le bytearray à convertir.
    :return: La liste de bits.
    """
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits

def pad10star1(data, rate):
    """
    Applique le padding pad10*1 pour aligner sur un multiple de 'rate' bits.

    :param data: Les données à padder.
    :param rate: Le taux de padding.
    :return: Les données paddées.
    """
    length = len(data) * 8  # longueur en bits (on travaille avec des tableaux bytearray)
    pad_len = rate - (length % rate)
    padded = bytearray(data)
    # Ajouter le bit 1
    padded += bytearray([0x80])
    # Ajouter les zéros nécessaires
    pad_zeros = (pad_len - 8) // 8
    padded += bytearray(pad_zeros)
    # Ajouter le dernier bit 1 (dans le dernier octet)
    if pad_len % 8:
        padded[-1] |= (1 << (pad_len % 8 - 1))
    return padded

def keccak_f(state):
    """
    La fonction de permutation Keccak-f.

    :param state: L'état interne à permuter.
    :return: L'état après permutation.
    """
    state = np.unpackbits(np.frombuffer(state, dtype=np.uint8)).reshape(5, 5, 64)
    for round_constant in ROUND_CONSTANTS:
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, round_constant)
    return np.packbits(state).tobytes()

def theta(state):
    """
    Étape Theta de la permutation Keccak.

    :param state: L'état interne.
    :return: L'état après l'étape Theta.
    """
    c = np.bitwise_xor.reduce(state, axis=1)
    d = np.bitwise_xor(c, np.roll(c, shift=1, axis=0))
    return np.bitwise_xor(state, d[:, np.newaxis, :])

def rho(state):
    """
    Applique une rotation circulaire sur chaque élément pour diffuser les bits.

    :param state: L'état interne.
    :return: L'état après rotation.
    """
    for x in range(5):
        for y in range(5):
            state[x, y] = np.roll(state[x, y], shift=ROTA_OFFSETS[x][y])
    return state

def pi(state):
    """
    Réorganise les éléments de la matrice 5×5 pour permuter leurs positions.

    :param state: L'état interne.
    :return: L'état après permutation des positions.
    """
    new_state = np.zeros_like(state)
    for x in range(5):
        for y in range(5):
            new_state[y, (2 * x + 3 * y) % 5] = state[x, y]
    return new_state

def chi(state):
    """
    Applique une transformation non linéaire pour mélanger les bits.

    :param state: L'état interne.
    :return: L'état après transformation non linéaire.
    """
    new_state = np.copy(state)
    for x in range(5):
        for y in range(5):
            new_state[x, y] ^= (~state[(x + 1) % 5, y] & state[(x + 2) % 5, y])
    return new_state

def iota(state, round_constant):
    """
    Introduit un élément de « salage » (salt) unique pour chaque tour.

    :param state: L'état interne.
    :param round_constant: La constante de tour.
    :return: L'état après introduction du salage.
    """
    state[0, 0] ^= np.unpackbits(np.array([round_constant], dtype=np.uint64).view(np.uint8))
    return state

def sha3(data, output_length, nb_squeeze):
    """
    Implémente Keccak, utilisé dans SHA-3 avec une sortie de longueur donnée en bits.
    On rajoute un paramètre nb_squeeze qui correspond au nombre d'essorage après la phase d'absorption.

    :param data: Les données à hacher.
    :param output_length: La longueur de la sortie en bits.
    :param nb_squeeze: Le nombre d'essorage après la phase d'absorption.
    :return: Le hachage résultant.
    """
    # Paramètres de la construction en éponge
    bitrate = 1600 - 2 * output_length
    capacity = 2 * output_length

    # Initialisation de l'état interne
    state = bytearray(200)  # État initial de 1600 bits (200 octets)

    # Padding des données
    padded_data = pad10star1(data, bitrate)

    # Phase d'absorption
    for i in range(0, len(padded_data), bitrate // 8):  # On prend un pas bitrate // 8 parce que notre tableau est de type bytearray donc avec des octets
        block = padded_data[i:i + bitrate // 8]
        for j in range(len(block)):
            state[j] ^= block[j]  # On prend le block de la taille bitrate et on XOR avec l'état initial (au début 0 puis ensuite on reprend le résultat suivant)
        state = keccak_f(state)  # On applique la fonction keccak sur l'état

    # Phase d'extraction
    output = bytearray()
    i = 0
    while (len(output) < output_length // 8) and (i < nb_squeeze):
        state = keccak_f(state)
        output += state[:bitrate // 8]
        i += 1

    return output[:output_length // 8]

def hash_password(password):
    """
    Crée un mot de passe haché en utilisant SHA-3.

    :param password: Le mot de passe en clair, rentré par l'utilisateur
    :return: Le hachage du mot de passe.
    """
    data = bytearray(password, "utf-8")
    hash_output = sha3(data, 256, 24)
    return hash_output
