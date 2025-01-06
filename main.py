import fonctions
import KDF
import Cobra
import getpass

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

def menu2(username):
    print(f'Bienvene {username}')

def connexion():

    username = input("Entrez votre nom d'utilisateur \n")

    testexistance = fonctions.verificationexistanceuser(username)

    if testexistance == 0:
        print(f'{username} n existe pas')
        menu1()

    certificatpresume = fonctions.generationcertificatcoffrefort()
    verificationcertificat = fonctions.verificationcertificat(certificatpresume)
    
    if verificationcertificat == 1:

        public_key,e,certificat = fonctions.recuperation_data_publique(username)
        engagement_chiffre = fonctions.engagementzkp(public_key,e)

        password = getpass.getpass("Entrez votre mot de passe \n")
        #FONCTION TRANSFORMANT MOT DE PASSE EN CLEF
        hash_mdp = KDF.hash_password(password)
        
        testmdp = fonctions.verification_connexion_mdp(username,hash_mdp)
        
        if testmdp == 0:
            print("Mot de Passe Incorrect --> Accès refusé")
            menu1()

        preuve,r = fonctions.calculpreuvezkp(e,public_key,engagement_chiffre,username,hash_mdp)

        connexion = fonctions.verificationzkp(preuve,e,certificat,r,public_key,engagement_chiffre)

        if connexion == 1:
            print("Connexion approuvée")
            menu2(username)
        else : 
            print("Connexion refusée")
            menu1()

    else :
        print("Coffre fort Compromis, ne pas rentrer d'informations confidentielles")
        return
    
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
    
    fonctions.creation_cle(username, hash_mdp) #RAJOUTER motdepasse DANS LES VARIABLES A ENTRER DANS LA FONCTION

    print("Vous allez être redirigé vers la page de connexion\n")
    connexion()
    

if __name__ == '__main__':
    print("Bienvenu sur le coffre fort le plus sécurisé ! \n ")
    menu1()