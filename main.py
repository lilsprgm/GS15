import fonctions
import KDF
import Cobra
import getpass


def menu1():#Menu permettant à l'utilisateur de soit se connecter, s'inscrire ou quitter le coffre fort
    menu = input("Que souhaitez vous faire ? \n <-1-> Connexion \n <-2-> Inscription \n <-3-> Quitter \n \n Veuillez entrer le numéro de fonction choisi\n")

    if menu == "1":
        connexion()
    elif menu == "2":
        inscription()
    elif menu == "3":
        exit()
    else:
        #Si l'action demandée n'existe pas, on demande à l'utilisateur de rentrer un nouveau numéro valide
        print("\nVeuillez entrez un numéro valide\n")
        return

def menu2(username,hash_mdp):#Menu permettant à l'utilisateur de choisir une fonction à effectuer parmi les fonctions suivantes
    run = True
    while run:
        menu = input(f'Bienvene {username}, que souhaitez vous faire ?\n<-1->Chiffrer un message\n<-2->Déchiffrer un message\n<-3->Chiffrer un fichier\n<-4->Déchiffrer un fichier\n<-5->Renitialiser le couple publique/privé + Certificat\n<-6->Suppression de l utilisateur\n<-7->Deconnexion\n')
        if menu == "1":
            message_a_chiffrer = input("Entrez le message que vous souhaitez chiffrer\n")
            fonctions.chiffrement_message(username,message_a_chiffrer,hash_mdp)
            menu2(username,hash_mdp)

        elif menu == "2":
            fonctions.dechiffrement_message(username,hash_mdp)

        elif menu == "3":
            fonctions.chiffrement_fichier(hash_mdp)

        elif menu == "4":
            fonctions.dechiffrage_fichier(hash_mdp)

        elif menu == "5":
            fonctions.renitialisationcle(username, hash_mdp)

        elif menu == "6":
            fonctions.removeutilisateur(username)
            run = False

        elif menu == "7":
            print("Deconnexion")
            run = False
        else:
            print("Veuillez entrer un numéro valable")

    return

def connexion():

    #Demande du login de l'utilisateur
    username = input("Entrez votre nom d'utilisateur \n")

    #Interdiction de se connecter en tant que coffrefort
    if username == "coffrefort":
        print("Connexion interdite")
        return

    #Verification que le nom d'utilisateur existe bien
    testexistance = fonctions.verificationexistanceuser(username)

    if testexistance == 0:
        print(f'{username} n existe pas')
        return

    #Verification du certificat du coffre fort en le faisant générer un nouveau et en le comparant avec celui dans authorité_certificat.json
    certificatpresume = fonctions.generationcertificatcoffrefort()
    verificationcertificat = fonctions.verificationcertificat(certificatpresume)
    
    if verificationcertificat == 1:

        #Récupération des données publiques de l'utilisateur afin d'engager le ZKP
        public_key,e,certificat = fonctions.recuperation_data_publique(username)
        engagement_chiffre = fonctions.engagementzkp(public_key,e)

        #Demande du mot de passe de l'utilisateur et hashage de celui ci
        password = getpass.getpass("Entrez votre mot de passe \n")
        hash_mdp = KDF.hash_password(password)
        
        #Verification que le mot de passe entré est bien le bon
        testmdp = fonctions.verification_connexion_mdp(username,hash_mdp)
        
        if testmdp == 0:
            print("Mot de Passe Incorrect --> Accès refusé")
            return

        #Mise en place du Challenge et du calcul de preuve pour le ZKP
        preuve,r = fonctions.calculpreuvezkp(e,public_key,engagement_chiffre,username,hash_mdp)

        #Verification du ZKP
        connexion = fonctions.verificationzkp(preuve,e,certificat,r,public_key,engagement_chiffre)

        if connexion == 1:
            print("Connexion approuvée")
            menu2(username,hash_mdp)
            return
        else : 
            print("Connexion refusée")
            return

    else :
        print("Coffre fort Compromis, ne pas rentrer d'informations confidentielles")
        return
    
def inscription():#Fonction pour inscrire l'utilisateur 
    
    username = input("Quel est votre nom d'utilisateur ?\n")

    #Verification que l'utilisateur n'essaye pas de se faire passer pour le coffrefort

    if username == "coffrefort":
        print("Nom d'utilisateur refusé")
        return
    
    #Verification que l'utilisateur n'existe pas déjà
    
    test = fonctions.verification_creation_user(username)

    if test == 0:
        print("Nom d'utilisateur déjà utilisé")
        return

    #Demande de mot de passe de l'utilisateur et hashage de celui ci    
    
    motdepasse = fonctions.verificationmdp()

    hash_mdp = KDF.hash_password(motdepasse)

    #Fonction permettant de créer les clés publiques / privées ainsi que le secret et le certificat de l'utilisateur

    fonctions.creation_cle(username, hash_mdp)

    #Redirection vers la page de connexion après l'inscription réussie

    print("Vous allez être redirigé vers la page de connexion\n")
    connexion()
    

if __name__ == '__main__':
    while True:
        print("Bienvenu sur le coffre fort le plus sécurisé ! \n ")
        menu1()