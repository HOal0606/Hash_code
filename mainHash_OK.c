#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <stdbool.h>

// Nombre password en claire maximun par fichier. 29000 lignes correspond a environ 3Mo/fichier

#define NbrPwdMax 29000

long long int calculFileSize(FILE *file){

    // calcule taille du fichier
    int fileSize;

    fileSize = ftell(file);

    fseek(file, 0, SEEK_END);

	fileSize = ftell(file);

	fseek(file, 0, 0);

    return fileSize;

}
char * hashPwd(char typeHash[], char inputPwd[], char * hashedPwdExt){

    // initialisationn paramètre de hash
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    int i;

    OpenSSL_add_all_digests();

	md = EVP_get_digestbyname(typeHash);

	if(!md) {
		printf("Type de hash a repréciser car le type %s\n n'est pas reconnu", typeHash);
		exit(1);
	}

	mdctx = EVP_MD_CTX_create();

    int inputPwdLen = strlen(inputPwd);


    char *hexaPwd= malloc(sizeof(char)*3000); // hexaPwd[100];
    char *hexaPwd256= malloc(sizeof(char)*3000); // hexaPwd[100];
  
    char *hashedPwd256 = malloc(sizeof(char)*3000);
    
    char *hashedPwd = malloc(sizeof(char)*3000);
    
    // ne prend pas en compte le retour chariot
    inputPwdLen = inputPwdLen - 1;
 
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, inputPwd, inputPwdLen);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    for(i = 0; i < md_len; i++){

            if(strcmp(typeHash,"sha256")){
                sprintf(hexaPwd256,"%02x", md_value[i]);
                strncat(hashedPwd256,hexaPwd256,2); //strncat(hashedPwd,hexaPwd,1); //2
            }else{
                sprintf(hexaPwd,"%02x", md_value[i]);
                strncat(hashedPwd,hexaPwd,2); //strncat(hashedPwd,hexaPwd,1); //2
            }

    }
     
    // cloture paramètre de hash
	EVP_MD_CTX_destroy(mdctx);
	EVP_cleanup(); 
    
    free(hexaPwd);
    

    if(strcmp(typeHash,"sha256")){
        strncat(hashedPwd256,"\n",1);
        return(hashedPwd256);
        free(hashedPwd256);


    }else{
        strncat(hashedPwd,"\n",1);

        return(hashedPwd);
        free(hashedPwd);
    }

}

typedef struct HashTable HashTable;
struct HashTable
{

    char *mdp[100];
    char *mdpMd5[129];

    char *mdpSha256[257];
    char *mallocEnd[2];


    HashTable *nextList;
};

typedef struct FirstList FirstList;
struct FirstList
{
    HashTable *firstMdp;
};

int malloSizeTable(int TAILLE_MAX, FILE *pwdDicoFile, HashTable ** mallocPtr, long long int *cptMdp, int * nbrMalloc, size_t * tested)
{
    FirstList *first1 = malloc(sizeof(*first1));

    HashTable * bufPtrMalloc;
     
    long long int nbrLineMax = NbrPwdMax;

    int mallocMax = 101;   
    
    int nbrMallocInt = 0;
    nbrMallocInt = *nbrMalloc;
    
    mallocPtr[nbrMallocInt] = malloc(sizeof(HashTable) * nbrLineMax);

    bufPtrMalloc = mallocPtr[nbrMallocInt];


    FILE * hashedFileBis = fopen("hashedFile1.txt", "w+"); 
    

    if(first1 == NULL || mallocPtr[nbrMallocInt] == NULL)
    {
        printf("allocation de la memoire non affectée\n");
        printf("veuillez recomencer\n");
        exit(EXIT_FAILURE);
    }

    char linepwdDicoFile[1000] = "";
    long long int nbPass = 0;
    int pointeLigne = 0;
    long long int cpt = 1;   
    char inputHashedFile[50];
    char indexfileStr[20];

    int passIf = 0;

    int nbFileHashSave = 0;

    int valid = 0;
    int indexFile = 1;
    char mallocEnd[2];
    char initEnd[2];
    strcpy(mallocEnd,"0");    
    strcpy(initEnd,"1");

    char mdp[100] = "mdp";
    char mdpMd5[129] = "mdpMd5";

    char mdpSha256[257] = "mdpSha256";

    rewind(pwdDicoFile);
 
    while (fgets(linepwdDicoFile, 1000, pwdDicoFile)!= NULL)
    {

        *cptMdp = *cptMdp + 1;

        *tested++;

        if((cpt > nbrLineMax) && (nbrMallocInt < 13))
        {

            strcpy((mallocPtr[nbrMallocInt]+cpt-1)->mallocEnd,initEnd);
            fwrite(&initEnd,1,strlen(&initEnd),hashedFileBis);   
            nbrMallocInt += 1;  

            *nbrMalloc = nbrMallocInt ; 
            indexFile += 1;  

            fclose(hashedFileBis);

            // création nouveau fichier avec index 

            strcpy(inputHashedFile, "");/**/
            strcat(inputHashedFile, "hashedFile");
            sprintf(indexfileStr,"%d",indexFile);
            strcat(inputHashedFile, indexfileStr); // a voir ici defaut type
            strcat(inputHashedFile, ".txt");

            hashedFileBis = fopen(inputHashedFile, "w+");

            mallocPtr[nbrMallocInt] = malloc(sizeof(HashTable) * nbrLineMax);

            if(mallocPtr[nbrMallocInt] == NULL)
            {
                printf("allocation de la memoire non affectée\n");
                printf("veuillez recomencer\n");
                exit(EXIT_FAILURE);
            }
          
            nbFileHashSave += 1;
            cpt = 0;                

        }
        else if ((cpt > nbrLineMax) && (nbrMallocInt > 12))
        {
            break;
        }

        strcpy((mallocPtr[nbrMallocInt]+cpt)->mdp, linepwdDicoFile);
        strcpy((mallocPtr[nbrMallocInt]+cpt)->mdpMd5, hashPwd("md5", linepwdDicoFile, &mdpMd5)); 
        strcpy((mallocPtr[nbrMallocInt]+cpt)->mdpSha256,  hashPwd("sha256", linepwdDicoFile, &mdpSha256));
        strcpy((mallocPtr[nbrMallocInt]+cpt)->mallocEnd,mallocEnd);

        strcpy(mdp,(mallocPtr[nbrMallocInt]+cpt)->mdp);

        strcpy(mdpMd5,(mallocPtr[nbrMallocInt]+cpt)->mdpMd5);
        
        strcpy(mdpSha256,(mallocPtr[nbrMallocInt]+cpt)->mdpSha256); 
        
        fwrite(&mdp,1,strlen(&mdp),hashedFileBis);
        fwrite(&mdpMd5,1,strlen(&mdpMd5),hashedFileBis);
        fwrite(&mdpSha256,1,strlen(&mdpSha256),hashedFileBis);

        cpt += 1;
        passIf = 1;

        pointeLigne += 3;

        nbFileHashSave += 1;
        
    }
    strcpy((mallocPtr[nbrMallocInt]+cpt-1)->mallocEnd,initEnd);
    fwrite(&initEnd,1,strlen(&initEnd),hashedFileBis);   

    fclose(hashedFileBis);
    
    return nbFileHashSave;
};

void mallocfree(HashTable *mdpHash)
{

    free(mdpHash);

};

void findMd5(char targetKeyMd5[129], char targetSha256[257],long long int *cptMdp, int *nbFileHashSave, int * nbrMalloc, HashTable ** mallocPtr, int monChoix)
{

    int target = 0;
    int indexMalloc = 1;
    int cptNbrMalloc = -1;
    int test = 22222;
    int cptEnd = 0; 

    int level_1, level_2, level_3, level_4, level_5, level_6, level_7, level_8, level_9, level_10;
    int level_11, level_12, level_13, level_14, level_15, level_16, level_17, level_18, level_19, level_20;
    int level_21, level_22, level_23, level_24, level_25, level_26, level_27, level_28, level_29, level_30;
    int level_31, level_32, level_33, level_34, level_35, level_36, level_37, level_38, level_39, level_40;
    int level_41, level_42, level_43, level_44, level_45, level_46, level_47, level_48, level_49, level_50;
    int level_51, level_52, level_53, level_54, level_55, level_56, level_57, level_58, level_59, level_60;
    int level_61, level_62, level_63, level_64, level_65, level_66, level_67, level_68, level_69, level_70;
    int level_71, level_72, level_73, level_74, level_75, level_76, level_77, level_78, level_79, level_80;
    int level_81, level_82, level_83, level_84, level_85, level_86, level_87, level_88, level_89, level_90;
    int level_91, level_92, level_93, level_94, level_95, level_96, level_97, level_98, level_99, level_100;

    
    char mallocKeyMd5[129];
    char mallocKeySha256[257];


    printf("\n");
    printf("\n");

    while (target == 0 )
    {

       
        if(cptNbrMalloc > *cptMdp){

            target = 0;
            break;
        }

        if(cptEnd  > *nbrMalloc-1){

            target = 0;
            break;
        }
        
        
        if(monChoix == 1){

            if (indexMalloc + 1 <= *nbrMalloc + 1 && level_1 !=1 && target !=1)
            {
                
                strcpy(mallocKeyMd5,((mallocPtr[indexMalloc]+cptNbrMalloc+1)->mdpMd5));

                test = strcmp(targetKeyMd5, mallocKeyMd5);

                if (test == 0)
                {
                    printf("FIND : mallocPtr[%d][%d] mdp =  %s\n", indexMalloc, cptNbrMalloc + 1, ((mallocPtr[indexMalloc] + cptNbrMalloc + 1)->mdp));
                    printf("FIND : mallocPtr[%d][%d] md5 =  %s\n", indexMalloc, cptNbrMalloc + 1, ((mallocPtr[indexMalloc] + cptNbrMalloc + 1)->mdpMd5));
                    printf("FIND : mallocPtr[%d][%d] sha256 =  %s\n", indexMalloc, cptNbrMalloc + 1, ((mallocPtr[indexMalloc] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }

                if (strcmp(((mallocPtr[indexMalloc]+cptNbrMalloc+1)->mallocEnd), "1")==NULL){

                    level_1 = 1; 
                    cptEnd += 1;  

                }  

                test = 22222; 

            }

            if (indexMalloc + 2 <= *nbrMalloc + 1 && level_2 != 1 && target != 1)
            {

                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 1] + cptNbrMalloc + 1)->mdpMd5));  

                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 1, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 1] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 1, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 1] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 1, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 1] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 1] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_2 = 1;
                    cptEnd += 1;

                }
                test = 22222;

                
            }
            if (indexMalloc + 3 <= *nbrMalloc + 1 && level_3 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 2] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 2, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 2] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 2, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 2] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 2, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 2] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 2] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_3 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }

            if (indexMalloc + 4 <= *nbrMalloc + 1 && level_4 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 3] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 3, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 3] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 3, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 3] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 3, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 3] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 3] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_4 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 5 <= *nbrMalloc + 1 && level_5 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 4] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 4, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 4] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 4, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 4] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 4, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 4] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 4] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_5 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 6 <= *nbrMalloc + 1 && level_6 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 5] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 5, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 5] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 5, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 5] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 5, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 5] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 5] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_6 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 7 <= *nbrMalloc + 1 && level_7 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 6] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 6, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 6] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 6, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 6] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 6, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 6] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 6] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_7 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 8 <= *nbrMalloc + 1 && level_8 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 7] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 7, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 7] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 7, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 7] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 7, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 7] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 7] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_8 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 9 <= *nbrMalloc + 1 && level_9 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 8] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 8, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 8] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 8, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 8] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 8, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 8] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 8] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_9 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 10 <= *nbrMalloc + 1 && level_10 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 9] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 9, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 9] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 9, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 9] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 9, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 9] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 9] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_10 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 11 <= *nbrMalloc + 1 && level_11 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 10] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 10, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 10] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 10, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 10] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 10, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 10] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 10] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_11 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 12 <= *nbrMalloc + 1 && level_12 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 11] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 11, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 11] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 11, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 11] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 11, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 11] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 11] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_12 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 13 <= *nbrMalloc + 1 && level_13 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 12] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 12, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 12] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 12, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 12] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 12, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 12] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 12] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_13 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 14 <= *nbrMalloc + 1 && level_14 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 13] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 13, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 13] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 13, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 13] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 13, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 13] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 13] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_14 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 15 <= *nbrMalloc + 1 && level_15 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 14] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 14, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 14] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 14, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 14] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 14, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 14] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 14] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_15 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 16 <= *nbrMalloc + 1 && level_16 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 15] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 15, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 15] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 15, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 15] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 15, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 15] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 15] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_16 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 17 <= *nbrMalloc + 1 && level_17 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 16] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 16, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 16] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 16, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 16] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 16, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 16] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 16] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_17 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 18 <= *nbrMalloc + 1 && level_18 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 17] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 17, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 17] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 17, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 17] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 17, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 17] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 17] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_18 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 19 <= *nbrMalloc + 1 && level_19 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 18] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 18, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 18] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 18, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 18] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 18, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 18] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 18] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_19 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 20 <= *nbrMalloc + 1 && level_20 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 19] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 19, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 19] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 19, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 19] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 19, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 19] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 19] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_20 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 21 <= *nbrMalloc + 1 && level_21 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 20] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 20, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 20] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 20, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 20] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 20, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 20] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 20] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_21 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 22 <= *nbrMalloc + 1 && level_22 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 21] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 21, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 21] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 21, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 21] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 21, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 21] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 21] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_22 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 23 <= *nbrMalloc + 1 && level_23 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 22] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 22, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 22] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 22, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 22] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 22, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 22] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 22] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_23 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 24 <= *nbrMalloc + 1 && level_24 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 23] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 23, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 23] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 23, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 23] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 23, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 23] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 23] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_24 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 25 <= *nbrMalloc + 1 && level_25 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 24] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 24, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 24] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 24, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 24] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 24, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 24] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 24] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_25 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 26 <= *nbrMalloc + 1 && level_26 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 25] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 25, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 25] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 25, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 25] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 25, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 25] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 25] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_26 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 27 <= *nbrMalloc + 1 && level_27 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 26] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 26, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 26] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 26, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 26] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 26, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 26] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 26] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_27 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 28 <= *nbrMalloc + 1 && level_28 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 27] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 27, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 27] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 27, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 27] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 27, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 27] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 27] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_28 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 29 <= *nbrMalloc + 1 && level_29 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 28] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 28, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 28] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 28, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 28] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 28, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 28] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 28] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_29 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 30 <= *nbrMalloc + 1 && level_30 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 29] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 29, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 29] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 29, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 29] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 29, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 29] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 29] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_30 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 31 <= *nbrMalloc + 1 && level_31 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 30] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 30, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 30] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 30, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 30] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 30, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 30] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 30] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_31 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 32 <= *nbrMalloc + 1 && level_32 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 31] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 31, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 31] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 31, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 31] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 31, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 31] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 31] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_32 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 33 <= *nbrMalloc + 1 && level_33 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 32] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 32, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 32] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 32, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 32] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 32, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 32] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 32] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_33 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 34 <= *nbrMalloc + 1 && level_34 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 33] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 33, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 33] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 33, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 33] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 33, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 33] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 33] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_34 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 35 <= *nbrMalloc + 1 && level_35 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 34] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 34, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 34] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 34, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 34] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 34, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 34] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 34] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_35 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 36 <= *nbrMalloc + 1 && level_36 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 35] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 35, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 35] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 35, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 35] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 35, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 35] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 35] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_36 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 37 <= *nbrMalloc + 1 && level_37 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 36] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 36, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 36] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 36, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 36] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 36, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 36] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 36] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_37 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 38 <= *nbrMalloc + 1 && level_38 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 37] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 37, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 37] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 37, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 37] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 37, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 37] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 37] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_38 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 39 <= *nbrMalloc + 1 && level_39 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 38] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 38, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 38] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 38, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 38] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 38, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 38] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 38] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_39 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 40 <= *nbrMalloc + 1 && level_40 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 39] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 39, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 39] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 39, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 39] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 39, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 39] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 39] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_40 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 41 <= *nbrMalloc + 1 && level_41 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 40] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 40, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 40] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 40, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 40] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 40, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 40] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 40] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_41 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 42 <= *nbrMalloc + 1 && level_42 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 41] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 41, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 41] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 41, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 41] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 41, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 41] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 41] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_42 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 43 <= *nbrMalloc + 1 && level_43 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 42] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 42, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 42] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 42, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 42] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 42, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 42] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 42] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_43 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 44 <= *nbrMalloc + 1 && level_44 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 43] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 43, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 43] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 43, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 43] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 43, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 43] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 43] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_44 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 45 <= *nbrMalloc + 1 && level_45 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 44] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 44, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 44] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 44, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 44] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 44, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 44] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 44] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_45 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 46 <= *nbrMalloc + 1 && level_46 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 45] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 45, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 45] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 45, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 45] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 45, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 45] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 45] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_46 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 47 <= *nbrMalloc + 1 && level_47 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 46] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 46, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 46] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 46, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 46] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 46, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 46] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 46] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_47 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 48 <= *nbrMalloc + 1 && level_48 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 47] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 47, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 47] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 47, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 47] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 47, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 47] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 47] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_48 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 49 <= *nbrMalloc + 1 && level_49 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 48] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 48, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 48] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 48, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 48] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 48, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 48] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 48] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_49 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 50 <= *nbrMalloc + 1 && level_50 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 49] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 49, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 49] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 49, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 49] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 49, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 49] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 49] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_50 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 51 <= *nbrMalloc + 1 && level_51 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 50] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 50, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 50] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 50, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 50] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 50, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 50] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 50] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_51 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 52 <= *nbrMalloc + 1 && level_52 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 51] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 51, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 51] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 51, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 51] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 51, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 51] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 51] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_52 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 53 <= *nbrMalloc + 1 && level_53 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 52] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 52, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 52] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 52, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 52] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 52, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 52] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 52] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_53 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 54 <= *nbrMalloc + 1 && level_54 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 53] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 53, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 53] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 53, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 53] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 53, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 53] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 53] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_54 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 55 <= *nbrMalloc + 1 && level_55 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 54] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 54, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 54] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 54, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 54] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 54, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 54] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 54] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_55 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 56 <= *nbrMalloc + 1 && level_56 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 55] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 55, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 55] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 55, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 55] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 55, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 55] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 55] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_56 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 57 <= *nbrMalloc + 1 && level_57 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 56] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 56, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 56] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 56, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 56] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 56, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 56] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 56] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_57 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 58 <= *nbrMalloc + 1 && level_58 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 57] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 57, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 57] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 57, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 57] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 57, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 57] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 57] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_58 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 59 <= *nbrMalloc + 1 && level_59 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 58] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 58, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 58] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 58, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 58] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 58, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 58] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 58] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_59 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 60 <= *nbrMalloc + 1 && level_60 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 59] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 59, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 59] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 59, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 59] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 59, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 59] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 59] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_60 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 61 <= *nbrMalloc + 1 && level_61 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 60] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 60, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 60] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 60, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 60] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 60, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 60] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 60] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_61 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 62 <= *nbrMalloc + 1 && level_62 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 61] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 61, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 61] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 61, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 61] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 61, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 61] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 61] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_62 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 63 <= *nbrMalloc + 1 && level_63 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 62] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 62, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 62] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 62, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 62] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 62, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 62] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 62] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_63 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 64 <= *nbrMalloc + 1 && level_64 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 63] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 63, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 63] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 63, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 63] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 63, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 63] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 63] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_64 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 65 <= *nbrMalloc + 1 && level_65 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 64] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 64, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 64] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 64, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 64] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 64, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 64] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 64] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_65 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 66 <= *nbrMalloc + 1 && level_66 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 65] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 65, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 65] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 65, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 65] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 65, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 65] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 65] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_66 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 67 <= *nbrMalloc + 1 && level_67 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 66] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 66, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 66] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 66, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 66] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 66, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 66] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 66] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_67 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 68 <= *nbrMalloc + 1 && level_68 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 67] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 67, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 67] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 67, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 67] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 67, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 67] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 67] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_68 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 69 <= *nbrMalloc + 1 && level_69 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 68] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 68, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 68] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 68, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 68] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 68, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 68] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 68] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_69 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 70 <= *nbrMalloc + 1 && level_70 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 69] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 69, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 69] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 69, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 69] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 69, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 69] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 69] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_70 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 71 <= *nbrMalloc + 1 && level_71 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 70] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 70, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 70] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 70, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 70] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 70, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 70] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 70] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_71 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 72 <= *nbrMalloc + 1 && level_72 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 71] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 71, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 71] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 71, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 71] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 71, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 71] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 71] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_72 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 73 <= *nbrMalloc + 1 && level_73 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 72] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 72, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 72] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 72, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 72] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 72, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 72] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 72] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_73 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 74 <= *nbrMalloc + 1 && level_74 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 73] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 73, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 73] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 73, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 73] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 73, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 73] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 73] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_74 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 75 <= *nbrMalloc + 1 && level_75 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 74] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 74, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 74] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 74, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 74] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 74, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 74] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 74] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_75 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 76 <= *nbrMalloc + 1 && level_76 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 75] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 75, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 75] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 75, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 75] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 75, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 75] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 75] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_76 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 77 <= *nbrMalloc + 1 && level_77 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 76] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 76, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 76] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 76, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 76] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 76, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 76] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 76] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_77 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 78 <= *nbrMalloc + 1 && level_78 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 77] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 77, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 77] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 77, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 77] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 77, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 77] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 77] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_78 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 79 <= *nbrMalloc + 1 && level_79 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 78] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 78, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 78] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 78, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 78] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 78, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 78] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 78] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_79 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 80 <= *nbrMalloc + 1 && level_80 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 79] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 79, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 79] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 79, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 79] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 79, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 79] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 79] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_80 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 81 <= *nbrMalloc + 1 && level_81 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 80] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 80, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 80] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 80, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 80] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 80, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 80] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 80] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_81 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 82 <= *nbrMalloc + 1 && level_82 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 81] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 81, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 81] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 81, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 81] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 81, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 81] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 81] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_82 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 83 <= *nbrMalloc + 1 && level_83 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 82] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 82, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 82] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 82, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 82] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 82, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 82] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 82] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_83 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 84 <= *nbrMalloc + 1 && level_84 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 83] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 83, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 83] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 83, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 83] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 83, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 83] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 83] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_84 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 85 <= *nbrMalloc + 1 && level_85 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 84] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 84, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 84] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 84, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 84] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 84, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 84] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 84] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_85 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 86 <= *nbrMalloc + 1 && level_86 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 85] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 85, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 85] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 85, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 85] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 85, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 85] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 85] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_86 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 87 <= *nbrMalloc + 1 && level_87 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 86] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 86, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 86] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 86, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 86] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 86, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 86] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 86] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_87 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 88 <= *nbrMalloc + 1 && level_88 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 87] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 87, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 87] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 87, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 87] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 87, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 87] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 87] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_88 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 89 <= *nbrMalloc + 1 && level_89 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 88] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 88, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 88] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 88, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 88] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 88, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 88] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 88] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_89 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 90 <= *nbrMalloc + 1 && level_90 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 89] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 89, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 89] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 89, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 89] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 89, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 89] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 89] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_90 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 91 <= *nbrMalloc + 1 && level_91 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 90] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 90, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 90] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 90, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 90] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 90, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 90] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 90] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_91 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 92 <= *nbrMalloc + 1 && level_92 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 91] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 91, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 91] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 91, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 91] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 91, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 91] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 91] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_92 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 93 <= *nbrMalloc + 1 && level_93 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 92] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 92, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 92] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 92, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 92] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 92, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 92] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 92] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_93 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 94 <= *nbrMalloc + 1 && level_94 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 93] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 93, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 93] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 93, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 93] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 93, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 93] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 93] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_94 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 95 <= *nbrMalloc + 1 && level_95 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 94] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 94, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 94] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 94, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 94] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 94, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 94] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 94] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_95 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 96 <= *nbrMalloc + 1 && level_96 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 95] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 95, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 95] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 95, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 95] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 95, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 95] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 95] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_96 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 97 <= *nbrMalloc + 1 && level_97 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 96] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 96, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 96] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 96, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 96] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 96, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 96] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 96] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_97 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 98 <= *nbrMalloc + 1 && level_98 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 97] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 97, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 97] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 97, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 97] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 97, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 97] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 97] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_98 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 99 <= *nbrMalloc + 1 && level_99 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 98] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 98, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 98] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 98, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 98] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 98, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 98] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 98] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_99 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
            if (indexMalloc + 100 <= *nbrMalloc + 1 && level_100 != 1 && target != 1)
            {
                strcpy(mallocKeyMd5, ((mallocPtr[indexMalloc + 99] + cptNbrMalloc + 1)->mdpMd5));
                test = strcmp(targetKeyMd5, mallocKeyMd5);
                if (test == 0)
                {
                    printf("Mdp trouvée : mallocPtr[%d][%d] mdp =  %s \n", indexMalloc + 99, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 99] + cptNbrMalloc + 1)->mdp));
                    printf("Md5 cherché : mallocPtr[%d][%d] md5 =  %s \n", indexMalloc + 99, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 99] + cptNbrMalloc + 1)->mdpMd5));
                    printf("Sha256 trouvé : mallocPtr[%d][%d] sha256 =  %s \n", indexMalloc + 99, cptNbrMalloc + 1, ((mallocPtr[indexMalloc + 99] + cptNbrMalloc + 1)->mdpSha256));
                    target = 1;
                    break;
                }
                if (strcmp(((mallocPtr[indexMalloc + 99] + cptNbrMalloc + 1)->mallocEnd), "1") == NULL)
                {
                    level_100 = 1;
                    cptEnd += 1;
                }
                test = 22222;
            }
        }
        
        
        cptNbrMalloc += 1;
        
    }

    if (target == 0)
    {

        printf("Code non retrouvé dans le dico :\n");
        printf("\n");
    }
    if(target == 1){


        printf("Code retrouvé dans le dico :\n");
        printf("\n");

    }
}

void main(int argc, char *argv[])
{
    int TAILLE_MAX = 10000;
    int nbFileHashSave = 1;
    char inputHashedFile[20]= "hashedFile1.txt";
    FILE *hashedFile;
    FILE *pwdDicoFile;
    char *nomFichierP;
    HashTable * mallocPtr[101]; // tableau de pointeur malloc
    char nomFichier[50];

    long long int cptMdp = 0;
    int nbrMalloc =1;
    int valid = 0; // verifie si le fichier a le bon format
    char myKey[100];
    char myKeyMd5[1129];
    char mykeyBuf[300];
    char mykeyBufMd5[129];
    char mykeySha256[257];


    size_t tested = 0;
    struct timeval tval;
    double start;
    double now;
    gettimeofday(&tval, NULL);
    start = tval.tv_sec + tval.tv_usec / 1000000.0;

    int monChoix = 0;
    int turn = 0;

     if (argc == 1 )
    {
        printf("non du fichier manquant (1)\n");
        printf(" argc = %d \n");

        printf("Enter le chemin et le nom du fichier : ");
        scanf("%s", nomFichier);

        nomFichierP = nomFichier;

        printf("nomFichierP: %s\n", nomFichierP);

        
    }else if (argc > 3 )
    {
        printf("non du fichier manquant (2)\n");
        printf(" argc = %d \n");

        printf("Enter le chemin et le nom du fichier : ");
        scanf("%s", nomFichier);

        nomFichierP = nomFichier;

        printf("nomFichierP: %s\n", nomFichierP);
        
    }   
    else
    {
        nomFichierP = argv[1]; 

    }

    pwdDicoFile = fopen(nomFichierP, "r+");

    //par défaut a 1 mais sera variable plus tard avec une fonction de vérification du format du fichier
    valid = 1; 

    // check contenu fichier dicoMdp.txt
    if (valid == 1)
    {

        // mise en mémoire du dictionnaire de mot de passe

        printf("Veuillez patienter le chargement est en cours \n");
        
        nbFileHashSave = malloSizeTable(TAILLE_MAX, pwdDicoFile, &mallocPtr, &cptMdp, &nbrMalloc, tested);

        gettimeofday(&tval, NULL);
        now = tval.tv_sec + tval.tv_usec / 1000000.0;
        double speed = tested / (now - start);
        fprintf(stderr, "%.3f M/s\n", speed / 1000000.0);

        while (turn == 0)
        {

            printf(" \n");

            printf("Il y a : %lld Mdp avec Hash archivé\n", cptMdp+1);

            printf("que souhaitez vous faire : \n");
            printf(" \n");            

            printf("==> tapez 0 pour quittez\n");

            printf("==> tapez 1 pour rechercher un hash de type md5 \n");

            printf("==> tapez 2 pour rechercher un hash de type sha256 \n");

 //           printf("==> tapez 3 pour rechercher un hash tout type (prend plus de temps)\n");
            printf("\n");

            scanf("%d", &monChoix);

            printf("\n");

            switch (monChoix)
            {

                case (1):
                    printf("==> veuillez taper la clé md5 \n");
                    scanf("%s", myKey);

                    //printf("==> la clé : %s \n", myKey);
                    printf("\n");

                    strncat(myKey,"\n",1);

                    findMd5(myKey, mykeySha256, &cptMdp, &nbFileHashSave, &nbrMalloc, &mallocPtr, monChoix);

                    break;

                case (2):
                    
                    printf("==> veuillez taper la clé sha256 \n");
                    scanf("%s", mykeySha256);

                   strncat(mykeySha256,"\n",1);

                    //printf("==> la clé : %s \n", mykeySha256);
                    printf("\n");

                    findMd5(myKey, mykeySha256, &cptMdp, &nbFileHashSave, &nbrMalloc, &mallocPtr, monChoix);
                    break;
/**
                case (3):

                    printf("==> veuillez taper la clé md5 \n");
                    scanf("%s", myKey);

                    strncat(myKey,"\n",1);
                    //printf("==> la clé : %s \n", myKey);

                    printf("==> veuillez taper la clé sha256 \n");
                    scanf("%s", mykeySha256);

                    strncat(mykeySha256,"\n",1);
                    //printf("==> la clé : %s \n", mykeySha256);

                    findMd5(myKey, mykeySha256, &cptMdp, &nbFileHashSave, &nbrMalloc, &mallocPtr, monChoix);
                    break;
/**/
                case (0):

                    printf(" vous quittez l'application \n");

                    turn = 1;
                    
                    break;

                default:
                    printf("veuillez relancer le programme\n");
                    break;
                    
            }
            

        }


    }
    else
    {

        printf("Failed to open the file\n");
    }

    // libération de mémoire malloc

    for( int id = 1; id < nbrMalloc+1; id++){


        free(mallocPtr[id]);
    }

}
