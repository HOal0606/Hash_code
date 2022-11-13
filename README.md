
Programme de recherche mot de passe en fonction d'un hash md5 ou sha256.

Le nombre password intiialisé par fichier (résultat) est de 29000 qui correspond a environ 3Mo/fichier.
Le fichier dicoMdp.txt contient 115000 password. Mais cela fonctionne avec beaucoup plus selon la ram du PC.
Il peut être modifié avec le #define NbrPwdMax 29000 en haut du fichier C.

Les fichiers sont créés dans le disque dur uniquement pour visualiser le résultat. Ils ne sont pas utilisés.
Les données sont enregistrées en mémoire avec la fonction malloc. Celle-ci est libérée à la fin du traitement.

Il y a 100 pointeurs de malloc alloué avec 29000 * la taille de la structure pour chacun d'eux enregistré dans un tableau de pointeurs.

Modification après la date de livraison prévu :

J'ai pu régler le bug dont je vous avais parlé pendant la soutenance concernant une égalité érronné de façon régulière sur certain hash md5.
C'était à cause d'un "strcat" de test que j'avais oublié.

J'ai également remplacer le traitement des passwords directement à partir de la mémoire sans lire les fichiers.
J'ai tout de même laissé la fonction de création de fichier de 3Mo.
  
pour l'exécution du programme : 

installation compilateur gcc : sudo apt install gcc

installation librairie : sudo apt install libssl-dev

compilation dans le repertoire courant : gcc -Wall hash_main.c -lcrypto

exécuter le programme avec ou sans nom de fichier en paramètre : ./a.out dicoMdp.txt

Les consignes seront données pendant le déroulement du programme


