import json
import random
import math
import getpass
import Cobra
import KDF
import shutil
import os

def creation_cle(user, hash_mdp): #Ajouter motdepasse en cle de chiffrement
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
        'autorisation': "oui",
        'p': p,
        'q': q,
        'private_key': d,
        'secret': Sn
    }

    #Création du fichier spécifique à l'utilisateur
    file_path = f'{user}.json'
    with open(file_path, "w") as json_file:
        json.dump(user_profile, json_file, indent=4)
    
    Cobra.sym_encryption_cobra(file_path, hash_mdp, 12)

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

def engagementzkp(public_key,e):
    #Engagement de ZKP en chiffrant un message aléatoire m qui devient M
    m = random.randint(0,public_key)
    #Calcul de l'engagement
    M = pow(m,e,public_key)
    return M

def calculpreuvezkp(e,public_key,engagement_chiffré,user,hash_mdp):
    #Choix du challenge r
    r = random.randint(0,e-1)
    file_path = f'{user}.json'
    Cobra.sym_decryption_cobra(file_path, hash_mdp,12)  # DECHIFFRER LE FICHIER USER.JSON AVEC LE HASH_MDP
    with open(file_path,'r') as file:
        content = file.read()
    clean_content=content.strip('\x00')
    data = json.loads(clean_content)
    Cobra.sym_encryption_cobra(file_path, hash_mdp,12)#RECHIFFRER LE FICHIER USER.JSON AVEC HASH_MDP
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
        return 1
    else:
       return 0

def verification_creation_user(user):
    #Test de si l'utilisateur existe déjà
    fichier_json = 'autorite_certificat.json'
    with open(fichier_json,'r') as file:
        data = json.load(file)
    variabletest=1
    for utilisateur in data["utilisateurs"]:
        if utilisateur["username"] == user:
            variabletest= 0
    return variabletest

def verificationmdp():
    #Faire rentrer le même mdp 2 fois à l'utilisateur afin de vérifier qu'il n'y ait pas d'erreur de saisie
    while True:
        # Faire entrer le mot de passe
        password = getpass.getpass("Entrez votre mot de passe\n")

        # Vérifier la longueur minimale
        if len(password) < 4:
            print("Votre mot de passe doit faire 4 caractères au minimum.")
            continue  # Recommencer la boucle

        # Faire entrer la confirmation du mot de passe
        confirmation = getpass.getpass("Confirmez votre mot de passe\n")

        # Vérifier si les mots de passe correspondent
        if confirmation == password:
            print("\nMot de passe créé\n")
            return password  # Retourner le mot de passe validé
        else:
            print("\nLes mots de passe sont différents, veuillez réessayer.\n")

def verification_connexion_mdp(username,hash_mdp): #Verification que le mdp entré par l'utilisateur est le bon
    #Copie du fichier username.json dans lequel se trouve les clefs privées chiffrées par le hashage du mot de passe
    #Cette copie du fichier permet de ne pas corrompre l'original en tentant de le dechiffrer
    file_path = f'{username}.json'
    new_file_path = f'{username}2.json'
    shutil.copy2(file_path,new_file_path)

    #Tentative de dechiffrer le json avec le hashage du mot de passe entré
    #Si lors de ce dechiffrement, la première ligne du fichier json est data[autorisation]=oui --> le mot de passe entré est le bon
    try: 
        Cobra.sym_decryption_cobra(new_file_path, hash_mdp, 12)
        with open(new_file_path,'r') as file:
            content = file.read()
        Cobra.sym_encryption_cobra(new_file_path, hash_mdp,12)
        #Filtrage des caractères nuls inscrits dans le fichier lors du dechiffrement
        clean_content=content.strip('\x00')
        data = json.loads(clean_content)
        
        data["autorisation"] = "oui"
        #Suppression de la copie du fichier
        os.remove(new_file_path)
        return 1
    except:
        os.remove(new_file_path)
        return 0
     
def generationcertificatcoffrefort():#Fonction pour faire générer un certificat au coffre fort afin de le comparer avec celui dans l'authorité de certification
    #Récupération du secret du coffre fort
    password = "Ceciestuncoffrefort"
    hash_mdp = KDF.hash_password(password)
    file_path = 'coffrefort.json'
    #Dechiffrement du fichier coffrefort.json
    Cobra.sym_decryption_cobra(file_path, hash_mdp, 12)
    with open(file_path,'r') as file:
        content = file.read()
    #Filtrage des caractères nuls
    clean_content=content.strip('\x00')
    data = json.loads(clean_content)
    secret = data["secret"]
    #Chiffrement du fichier coffrefort.json
    Cobra.sym_encryption_cobra(file_path, hash_mdp, 12)
    #Récupération des données publiques du coffre fort afin de générer le certificat en fonction du secret récupéré precedemment et de la clé publique
    file_path = 'autorite_certificat.json'
    with open(file_path,'r') as file:
        data = json.load(file)
    public_key = None
    e = None
    for utilisateur in data["utilisateurs"]:
        if utilisateur["username"] == "coffrefort":
            public_key = utilisateur["public_key"][0]
            e = utilisateur["public_key"][1]
    certificat = pow(secret,e,public_key)
    return certificat

def verificationcertificat(certificatpresume):#Comparaison entre le certificat généré par le coffre fort et celui inscrit dans authorité de certification
    #Récupération du certificat publique du coffre fort
    file_path = 'autorite_certificat.json'
    with open(file_path,'r') as file:
        data = json.load(file)
    certificat = None
    for utilisateur in data["utilisateurs"]:
        if utilisateur["username"] == "coffrefort":
            certificat = utilisateur["certificat"]
    #Comparaison avec le certificat présumé
    if certificatpresume == certificat:
        return 1
    else:
        return 0
    
def verificationexistanceuser(username):#Fonction pour vérifier si un user existe déjà
    #Récupération des données dans l'authorité de certification
    file_path = 'autorite_certificat.json'
    with open(file_path,'r') as file:
        data = json.load(file)
    resultat = 0
    #Test de la présence du username dans la donnée de l'authorité de certification
    for utilisateur in data["utilisateurs"]:
        if utilisateur["username"] == username:
            resultat = 1
    return resultat

def chiffrement_message(username,message_à_chiffrer,hash_mdp):#Fonction pour chiffrer un message
    #Création d'un fichier au nom de l'utilisateur pour stocker le message
    file_path = f'{username}_message_chiffré.json'
    message = {
        'autorisation': "oui",
        'message': message_à_chiffrer
    }
    #Stockage du message + Chiffrement du fichier
    with open(file_path, "w") as json_file:
        json.dump(message, json_file, indent=4)
    Cobra.sym_encryption_cobra(file_path, hash_mdp,12)
    print("Message chiffré")

def dechiffrement_message(username,hash_mdp):#Fonction pour déchiffrer le message écrit par l'utilisateur
    #Déchiffrement + ouverture du fichier dans lequel est le message
    file_path = f'{username}_message_chiffré.json'
    Cobra.sym_decryption_cobra(file_path, hash_mdp, 12)
    with open(file_path,'r') as file:
        content = file.read()
    #Filtrage des caractères nuls
    clean_content=content.strip('\x00')
    data = json.loads(clean_content)
    message_clair = data["message"]
    #Print du message
    print(f'Le message déchiffré est :{message_clair}')
    #Suppression du fichier dans lequel était le message
    os.remove(file_path)

def chiffrement_fichier(hash_mdp):#Fonction permettant de chiffrer un fichier exterieur et de le stocker dans le coffre fort
    fichier = input("Veuillez entrer le nom du fichier.son extension\n")
    #Verification que le fichier n'est pas un fichier déjà dans le coffre fort
    dossier = os.path.dirname(os.path.abspath(__file__)) # Commande pour avoir le chemin du dossier dans lequel est le main.py
    chemin_fichier = os.path.join(dossier,fichier) #Commande pour joindre le chemin du main.py + nom du fichier
    if os.path.isfile(chemin_fichier):#Test de si le fichier existe 
        print("Il est interdit de chiffrer des fichiers déjà dans le coffre fort")
        return 0
    else:
        #Demande du chemin afin d'aller chercher le fichier sur la machine de l'utilisateur
        path = input("Entrez le chemin du fichier que vous souhaitez chiffrer\n")
        file_path = os.path.join(path,fichier)
        #Verification que le fichier existe 
        if os.path.exists(file_path):
            #Couper / Coller le fichier dans le coffre et le chiffrer avec la hash du mdp
            try:
                shutil.move(file_path,chemin_fichier)
                Cobra.sym_encryption_cobra(fichier,hash_mdp,12)
                print("Chiffrement terminé\n")
            except:
                print("Erreur lors de l'importation du fichier ou du chiffrement de celui ci")
        else:
            print("Le fichier n'existe pas")

def dechiffrage_fichier(hash_mdp): #Fonction permettant de déchiffrer un fichier à l'intérieur du coffre fort
    #Liste des fichiers à l'utilisateur afin qu'il choississe lequel déchiffrer
    dossier = os.path.dirname(os.path.abspath(__file__))
    listefichiers=os.listdir(dossier)
    print("Quel fichier (vous appartenant) souhaitez vous déchiffrer\n")
    for file in listefichiers:
        chemin_complet = os.path.join(dossier,file)
        if os.path.isfile(chemin_complet):
            print(file)
    print("\n")
    fichier = input("")
    #Récupération du nom du fichier et de son extension dans 2 variables différentes
    sans_extension = os.path.splitext(fichier)[0]
    extension = os.path.splitext(fichier)[1]
    #L'objectif est encore une fois de ne pas toucher au document originel mais de copier/coller sur la machine de l'utilisateur le document déchiffré par sa clé/
    #Si l'utilisateur a choisi un fichier lui appartenant, alors il retrouvera un fichier en clair
    #Si l'utilisateur a choisi un fichier ne lui appartenant pas, alors il aura un fichier compromis mais qui n'aura aucune conséquence sur l'originel
    try:
        #Copie du fichier originel + dechiffrement 
        newfichier = f'{sans_extension}2{extension}'
        shutil.copy2(fichier,newfichier)
        Cobra.sym_decryption_cobra(newfichier,hash_mdp,12)
        #Demande a l'utilisateur où souhaite il avoir le fichier sur sa machine
        chemin_fichier_déchiffé = input("Où souhaitez vous que votre fichier soit déposé ?\n")
        if chemin_fichier_déchiffé == dossier:
            print("Il n'est pas autorisé de sauvegarder ce fichier dans le coffre fort\n")
            os.remove(newfichier)
            return
        #Couper / Coller la copie du fichier déchiffré sur la machine de l'utilisateur
        chemin = os.path.join(chemin_fichier_déchiffé,newfichier)
        shutil.move(newfichier,chemin)
        fichierfinal = os.path.join(chemin_fichier_déchiffé,fichier)
        #Rename du fichier afin qu'il ait son nom originel
        os.rename(chemin,fichierfinal)
        print(f"Fichier clair déposé au chemin suivant : {fichierfinal}")
    except:
        print("Erreur durant le déchiffrement")
        return
    
def renitialisationcle(username, hash_mdp): #Renitialisation des données dans l'authorité de certification et dans le fichier username.json
    #Suppression des données de l'utilisateur dans le fichier authorité certificat
    with open('autorite_certificat.json', 'r') as file:
        data = json.load(file)
    data['utilisateurs'] = [user for user in data['utilisateurs'] if user['username'] != f'{username}']
    with open('autorite_certificat.json','w') as file:
        json.dump(data,file,indent=4)
    #Suppression du fichier username.json
    os.remove(f'{username}.json')
    #Création d'un nouveau jeu de clé
    creation_cle(username,hash_mdp)
    print("Renitialisation du couple clé publique/clé privé et du certificat")

def removeutilisateur(utilisateur): #Meme fonction que precedemment, juste pas de nouvelles clés à la fin de celle ci
    #Le mot de passe est demandé afin d'éviter les suppressions d'utilisateur par erreur
    password = getpass.getpass("Entrez votre mot de passe pour confirmer la suppression de l'utilisateur (ne rien entrer pour annuler) \n")
    hash_mdp = KDF.hash_password(password)
    test_mdp = verification_connexion_mdp(utilisateur,hash_mdp)
    if test_mdp == 1:
        with open('autorite_certificat.json', 'r') as file:
            data = json.load(file)
        data['utilisateurs'] = [user for user in data['utilisateurs'] if user['username'] != f'{utilisateur}']
        with open('autorite_certificat.json','w') as file:
            json.dump(data,file,indent=4)
        os.remove(f'{utilisateur}.json')
        print(f'Utilisateur {utilisateur} supprimé')
    else:
        print(f"Annulation de la suppression de l'utilisateur {utilisateur}")
        return