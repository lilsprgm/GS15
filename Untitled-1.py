import random
import math

def is_prime(n):
    n=int(n)
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def creationcle():
    
    p=random.randint(0,10**9)

    while is_prime(p) is False:
        p=random.randint(0,10**9)

    q=random.randint(0,10**9)

    while is_prime(q) is False:
        q = random.randint(0,10**9)

    n = p * q

    phi_n = (p-1)*(q-1)

    e = 65537

    while pgcd(e,phi_n) != 1:
        creationcle()
    
    d = pow(e,-1,phi_n)

    Sn = random.randint(0,10**8)
    Cert = pow(Sn,e,n) 
    
    return(n,p,q,e,phi_n,d,Cert,Sn)

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

n,p,q,e,phi_n,d,cert,Sn = creationcle()

print("n=",n,"\np=",p,"\nq=",q,"\ne=",e,"\nphi(n)=",phi_n,"\nd=",d)

print("<==================================Etape 1 : Entagement de Nicolas=======================================>")
message_clair = random.randint(1,n-1)
message_chiffre = pow(message_clair,e,n)
print(f"Le message clair envoyé par Nicolas est {message_clair} qui devient {message_chiffre}")
print(f"Le certificat est {cert}")

print("<==================================Etape 2 : Choix du Challenge par Rémi=======================================>")
r = random.randint(1, e-1)
print(f"Le challenge choisit par Rémi est r={r}")

print("<==================================Etape 3: Calcul de la preuve par Nicolas=======================================>")
preuve1=pow(Sn,-r,n)
preuve=(message_clair*preuve1)%n

print(f"La preuve calculée par Nicolas est la suivante : {preuve}")

print("<==================================Etape 4: Verification de la preuve par Remi=======================================>")
resultat=(pow(preuve,e)*pow(cert,r))%n

if resultat == message_chiffre:
    print("Verification acceptée")
else:
    print("Verifications refusée")