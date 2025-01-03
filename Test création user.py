import json
import random
import math

def creation_cle(user):
    #Test de si l'utilisateur existe déjà
    fichier_json = 'autorite_certificat.json'
    with open(fichier_json,'r') as file:
        data = json.load(file)
    for utilisateur in data["utilisateurs"]:
        if utilisateur["username"] == user:
            print("<============================!! L'utilisateur existe déjà !!===========================================>")
            return
    print("<=================================================================Création du couple de clé publique/privée ==================================================>")
    #Limite de 1024 bits pour la création de clé
    upper_limit = 2**1024 - 1
    #Génération p et q pour faire n (clé publique)
    p=random.randint(0,upper_limit)
    #Verification de que p est bien premier
    while is_prime_miller_rabin(p) is False:
        p=random.randint(0, upper_limit)  
    q=random.randint(0,upper_limit)
    #Verification que q est bien premier
    while is_prime_miller_rabin(q) is False:
        q = random.randint(0,upper_limit)
    #Creation de la clé publique (n,e) + clé privée d    
    n=p*q
    phi_n=(p-1)*(q-1)
    e = 65537
    #ReRoll de l'algo si phi et e sont pas premiers entre eux
    while pgcd(e,phi_n) != 1:
        creation_cle(user)

    d = pow(e,-1,phi_n)
    #Création du certificat
    Sn = random.randint(0,upper_limit)
    Cert = pow(Sn,e,n)

#Ecriture du certificat et de la public_key dans le json authorité de certificat
    user_profile={
        'username': user,
        'public_key': (n,e),
        'certificat': Cert
    }

    #Chemin du fichier json
    fichier_json = 'autorite_certificat.json'
    #Récupération de la Data
    with open(fichier_json, 'r') as f:
        data_existante = json.load(f)
    #Ajout de la nouvelle donnée
    data_existante["utilisateurs"].append(user_profile)
    #Ecriture dans le fichier JSON
    with open(fichier_json, 'w') as f:
        json.dump(data_existante, f, indent=4)

#Ecriture du la clé privée + Secret dans un fichier appartenant à l'utilisateur

    user_profile={
        'p': p,
        'q': q,
        'private_key': d,
        'secret': Sn
    }

    #Création du fichier spécifique à l'utilisateur
    file_path = f'{user}.json'
    with open(file_path, "w") as json_file:
        json.dump(user_profile, json_file, indent=4)

    print("<=======================================================Création réussie===============================>")

def is_prime_miller_rabin(n, k=40):  # k est le nombre d'itérations
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Écrire n-1 sous la forme 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Effectuer k tests de Miller-Rabin
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)  # a^d % n
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def pgcd(a,b):
    
    if a < b:
        c = a
        a = b
        b= c
    elif a == b:
        return 0
    
    listedesrestes=[]
    quotient = a//b
    reste = a%b

    listedesrestes.append(reste)

    while reste>0:
        a=b
        b=reste
        reste=a%b
        quotient = a//b
        listedesrestes.append(reste)    

    pgcd = listedesrestes[len(listedesrestes)-2]
    return pgcd

def recuperation_data_publique(user):

    #Ouverture du fichier json autorité certif afin de récupérer son certif + Clé Publique    
    file_path = 'autorite_certificat.json'
    with open(file_path,'r') as file:
        data = json.load(file)

    #Récupération de la public_key
    public_key = None
    e = None
    certificat = None

    for utilisateur in data["utilisateurs"]:
        if utilisateur["username"] == user:
            public_key = utilisateur["public_key"][0]
            e = utilisateur["public_key"][1]
            certificat = utilisateur["certificat"]

    return public_key,e,certificat

def engagementzkp(public_key,e,user):
    #Engagement de ZKP en chiffrant un message aléatoire m qui devient M avec un m appartenant a Zp
    #Récupération de p pour générer m
    file_path = f'{user}.json'
    with open(file_path,'r') as file:
        data = json.load(file)
    p=data['p']
    q=data['q']
    if p>q:
        p=q
    m = random.randint(0,p)
    #Calcul de l'engagement
    M = pow(m,e,public_key)
    return M

def calculpreuvezkp(e,public_key,engagement_chiffré,user):
    #Choix du challenge r
    r = random.randint(0,e-1)
    #Récupération de la clé privée par l'User
    file_path = f'{user}.json'
    with open(file_path,'r') as file:
        data = json.load(file)
    secret=data["secret"]
    private_key=data["private_key"]
    #Récupération de l'engagement en clair
    engagement_clair=pow(engagement_chiffré,private_key,public_key)
    #Premier calcul de la preuve avec le secret du certificat de l'utilisateur
    preuve1=pow(secret,-r,public_key)
    preuve=(engagement_clair*preuve1)%public_key
    return preuve,r 

def verificationzkp(preuve,e,certificat,r,public_key,engagement_chiffré):
    #Calcul de Preuve^e.Cert^r 
    resultat1=pow(preuve,e,public_key)
    resultat2=pow(certificat,r,public_key)
    resultat=(resultat1*resultat2)%public_key
    #Verification engagement = resultat
    if resultat == engagement_chiffré:
        print("Verification acceptée")
    else:
       print("Verification refusée")

user="Enzo"
creation_cle(user)
public_key,e,certificat = recuperation_data_publique(user)
engagement_chiffré = engagementzkp(public_key,e,user)
preuve,r = calculpreuvezkp(e,public_key,engagement_chiffré,user)
verificationzkp(preuve,e,certificat,r,public_key,engagement_chiffré)
