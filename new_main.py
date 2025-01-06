import fonctions
import KDF
import Cobra

def menu1():
    menu = input("Que souhaitez vous faire ? \n <-1-> Connexion \n <-2-> Inscription \n <-3-> Quitter \n \n Veuillez entrer le numéro de fonction choisi\n")

    if menu == "1":
        connexion()
    elif menu == "2":
        inscription()
    elif menu == "3":
        return
    else:
        print("\nVeuillez entrez un numéro valide\n")
        menu1()

def connexion():
    print("Connexion")

def inscription():
    
    username = input("Quel est votre nom d'utilisateur ?\n")

    if username == "coffrefort":
        print("Nom d'utilisateur refusé")
        inscription()
    
    test = fonctions.verification_creation_user(username)

    if test == 0:
        print("Nom d'utilisateur déjà utilisé")
        inscription()
    
    motdepasse = fonctions.verificationmdp()

    hash_mdp = KDF.hash_password(motdepasse)#AJOUTER LES FONCTIONS NECESSAIRES POUR TRANSFORMER MOTDEPASSE EN CLE DE CHIFFREMENT
    
    fonctions.creation_cle(username) #RAJOUTER motdepasse DANS LES VARIABLES A ENTRER DANS LA FONCTION
    


print("Bienvenu sur le coffre fort le plus sécurisé ! \n ")
menu1()