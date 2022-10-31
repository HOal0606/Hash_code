#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

typedef struct HashTable HashTable;
struct HashTable
{
    char *keyHash[100];
    char *mdp[100];
    char *mdpMd5[100];
    char *typeHash1[15];
    char *mdpSha256[100];
    char *typeHash2[15];

    HashTable *nextList;
};

typedef struct FirstList FirstList;
struct FirstList
{
    HashTable *firstMdp;
};

FirstList *malloSizeTable(int TAILLE_MAX, FILE *fp)
{
    FirstList *first1 = malloc(sizeof(*first1));
    HashTable *mdpHash = malloc(sizeof(*mdpHash));

    if (first1 == NULL || mdpHash == NULL)
    {
        printf("l'allocation de la mémoire n'as pas fonctionné \n");
        printf("veuillez recomencer \n");
        exit(EXIT_FAILURE);
    }

    char ligneFp[10000] = "";
    int nbPass = 0;
    int pointeLigne = 6;
    int cpt = 0;
    int passIf = 0;
    int cptMdp = 0;
    // int keyHash = 0;
    int valid = 0;

    while (fgets(ligneFp, TAILLE_MAX, fp) != NULL)
    {

        if (cpt != 0)
        {

            if (cpt == 1 && passIf == 0)
            {

                printf("==============\n");
                strcpy(mdpHash->keyHash, ligneFp);

                cpt += 1;
                passIf = 1;
            }
            if (cpt == 2 && passIf == 0)
            {

                strcpy(mdpHash->mdp, ligneFp);

                cpt += 1;
                passIf = 1;
            }
            if (cpt == 3 && passIf == 0)
            {

                strcpy(mdpHash->mdpMd5, ligneFp);

                cpt += 1;
                passIf = 1;
            }
            if (cpt == 4 && passIf == 0)
            {

                strcpy(mdpHash->typeHash1, ligneFp);

                cpt += 1;
                passIf = 1;
            }
            if (cpt == 5 && passIf == 0)
            {

                strcpy(mdpHash->mdpSha256, ligneFp);

                cpt += 1;
                passIf = 1;
            }
            if (cpt == 6 && passIf == 0)
            {

                strcpy(mdpHash->typeHash2, ligneFp);

                cpt = 1;
                passIf = 1;
            }

            passIf = 0;
            nbPass += 1;
        }

        if (nbPass == pointeLigne)
        {

            pointeLigne += 6;

            cptMdp = cptMdp + 1;
            break;
        }

        if (strcmp(ligneFp, "debut") && valid == 0)
        {
            if (valid == 0)
            {
                cpt = 1;
                valid = 1;
            }
        }
    }

    mdpHash->nextList = NULL;

    first1->firstMdp = mdpHash;

    return (first1);
};

void mallocfree(HashTable *mdpHash)
{

    free(mdpHash);
};

int checkFile(FILE *fp, int TAILLE_MAX)
{

    char ligneFp[10000] = "";
    int valid = 0;
    int nbPass = 0;

    int cptMdp = 0;
    int pointeLigne = 6;

    while (fgets(ligneFp, TAILLE_MAX, fp) != NULL)
    {
        if (strcmp(ligneFp, "debut") || valid == 1)
        {

            if (valid == 0)
            {

                printf("le fichier a le bon format \n");
                printf("debut chargement...\n");

                valid = 1;
            }

            if (nbPass == pointeLigne && valid == 1)
            {

                pointeLigne += 6;

                cptMdp = cptMdp + 1;
            }

            nbPass += 1;
        }
        else
        {

            printf("le fichier n'a pas le bon format \n");
        }
    }

    return cptMdp;
}

void findMd5(char mykey[100], int cptMdp, FirstList *first1)
{

    char checkKey[100];
    char checkKey2[100];
    int test = 20;

    char mdp[100];
    char mdpMd5[100];
    char typeHash1[15];
    char mdpSha256[100];
    char typeHash2[15];
    int target = 0;

    int nbcycle = 0;

    if (first1 == NULL)
    {
        exit(EXIT_FAILURE);
    }

    HashTable *showMdp = first1->firstMdp;

    while (showMdp != NULL)

    {

        strcpy(checkKey2, showMdp->mdpMd5);

        strcpy(checkKey, mykey);

        test = strcmp(checkKey, checkKey2);

        if (test == -10)
        {

            printf("Code retrouvé :\n");

            printf("%s\n", showMdp->mdp);
            printf("%s\n", showMdp->typeHash1);
            printf("%s\n", showMdp->mdpMd5);
            printf("%s\n", showMdp->typeHash2);
            printf("%s\n", showMdp->mdpSha256);

            target = 1;
        }

        nbcycle += 1;

        showMdp = showMdp->nextList;
    }

    if (target == 0)
    {

        printf("Code non retrouvé dans le dico :\n");
    }
}

int insertMdp(FirstList *first1, int cptMdp, int TAILLE_MAX, FILE *fp, int nbrMdp)
{
    /* Création du nouvel élément */
    HashTable *newMdp = malloc(sizeof(*newMdp));

    if (first1 == NULL || newMdp == NULL)
    {
        exit(EXIT_FAILURE);
    }

    char ligneFp[10000] = "";
    int nbPass = 0;
    int pointeLigne = 6;
    int cpt = 0;
    int passIf = 0;

    int cptMdpBis = 0;

    int valid = 0;

    while (fgets(ligneFp, TAILLE_MAX, fp) != NULL)
    {

        if (cpt != 0)
        {

            if (nbrMdp == cptMdpBis)
            {

                if (cpt == 1 && passIf == 0)
                {

                    printf("==============\n");
                    strcpy(newMdp->keyHash, ligneFp);

                    cpt += 1;
                    passIf = 1;
                }
                if (cpt == 2 && passIf == 0)
                {

                    strcpy(newMdp->mdp, ligneFp);

                    cpt += 1;
                    passIf = 1;
                }
                if (cpt == 3 && passIf == 0)
                {

                    strcpy(newMdp->mdpMd5, ligneFp);

                    cpt += 1;
                    passIf = 1;
                }
                if (cpt == 4 && passIf == 0)
                {

                    strcpy(newMdp->typeHash1, ligneFp);

                    cpt += 1;
                    passIf = 1;
                }
                if (cpt == 5 && passIf == 0)
                {

                    strcpy(newMdp->mdpSha256, ligneFp);

                    cpt += 1;
                    passIf = 1;
                }
                if (cpt == 6 && passIf == 0)
                {

                    strcpy(newMdp->typeHash2, ligneFp);

                    cpt = 1;
                    passIf = 1;
                }
            }

            passIf = 0;
            nbPass += 1;
        }

        if (nbPass == pointeLigne)
        {

            pointeLigne += 6;

            cptMdpBis = cptMdpBis + 1;
        }

        if (strcmp(ligneFp, "debut") && valid == 0)
        {
            if (valid == 0)
            {
                cpt = 1;
                valid = 1;
            }
        }
    }

    /* Insertion de l'élément au début de la liste */
    newMdp->nextList = first1->firstMdp;
    first1->firstMdp = newMdp;

    return nbrMdp;
}

int main(int argc, char *argv[])
{
    int TAILLE_MAX = 10000;
    FILE *fp;
    char *nomFichierP;
    char nomFichier[50];

    int cptMdp = 0;
    int valid = 0; // verifie si le fichier a le bon format
    char myKey[100];
    char myKeyMd5[100];
    char mykeyBuf[100];
    char mykeyBufMd5[100];

    int monChoix = 0;

    // ouverture fichier type dicoMdp.txt
    if (argc < 2)
    {
        printf("non du fichier manquant\n");

        printf("Enter le chemin et le nom du fichier : ");
        scanf("%s", nomFichier);

        nomFichierP = nomFichier;

        printf("nomFichierP: %s\n", nomFichierP);

        fp = fopen(nomFichierP, "r+");
    }
    else
    {
        nomFichierP = argv[1];
        printf("nomFichierP: %s\n", nomFichierP);

        fp = fopen(nomFichierP, "r+");
    }

    if (fp != NULL)
    {
        cptMdp = checkFile(fp, TAILLE_MAX);
        if (cptMdp > 0)
        {

            valid = 1;
            printf("Il y a : %d Mdp avec Hash archivé\n", cptMdp);
        }
    }

    int nbrMdp = 1;
    // check contenu fichier dicoMdp.txt
    if (valid == 1)
    {

        // mise en mémoire du dictionnaire de mot de passe
        fp = fopen(nomFichierP, "r+");

        FirstList *firstListe = malloSizeTable(TAILLE_MAX, fp);
        fp = fopen(nomFichierP, "r+");

        for (int i = 0; i <= cptMdp; i++)
        {

            // int nbr;
            fp = fopen(nomFichierP, "r+");

            nbrMdp = insertMdp(firstListe, cptMdp, TAILLE_MAX, fp, nbrMdp);

            nbrMdp += 1;
        }

        fp = fopen(nomFichierP, "r+");

        if (fp != NULL)
        {

            printf(" \n");

            printf("Il y a : %d Mdp avec Hash archivé\n", cptMdp);

            printf("que souhaitez vous faire : \n");
            printf(" \n");
            printf("==> tapez 1 pour rechercher un hash de type md5 \n");

            printf("==> tapez 2 pour rechercher un hash de type sha256 \n");

            printf("==> tapez 3 pour rechercher un hash tout type (prend plus de temps)\n");
            printf("\n");

            scanf("%d", &monChoix);

            printf("mon choix : %d\n", monChoix);

            switch (monChoix)
            {

            case (1):
                printf("==> veuillez taper la clé md5 \n");
                scanf("%s", myKey);

                strcpy(mykeyBuf, "hashMdp:"); // "mdpMd5:");

                strcat(mykeyBuf, myKey);

                strcpy(myKey, mykeyBuf);
                printf("==> la clé : %s \n", myKey);

                findMd5(myKey, cptMdp, firstListe);

            case (2):

            case (3):
            }
        }
    }
    else
    {

        printf("Failed to open the file\n");
    }

    // mise en mémoire contenu fichier sous forme de structure

    //	HashTable* myHash;
    //  	myHash = mallocsize(); // affectation de mémoire avec malloc

    // libération de mémoire avec malloc
    // mallocfree(mdpHash);
    // fclose(inFile);

    //free(nbrMdp);
    fclose(fp);

    return (0);
}
