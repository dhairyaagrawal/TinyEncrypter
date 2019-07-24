#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

void encrypt(char* inputFile);
void decrypt(char* ciphertext, char* cipher);
void shuffle(unsigned char* array, int size);

void shuffle(unsigned char* array, int size) {
	if(size > 1) {
		for(int i = 0; i < size; ++i) {
			int j = rand() % size;
			unsigned char temp = array[j];
			array[j] = array[i];
			array[i] = temp;
		}
	}
}

void encrypt(char* inputFile) {
    //Variables for file operations
    FILE* fp;
    unsigned int fileSize;

    //Variables for random sub table, random shift of bytes and key
    unsigned char randomSub[256];
    unsigned char randomShift;
    unsigned char key[32];

    //Random seed function
    srand(time(NULL));

    //Generate sub table for confusion
    for(int i = 0; i < 256; ++i) {
        randomSub[i] = i;
    } 
    shuffle(randomSub, 256);
    
    //Print table
    printf("Random Sub: ");
    for(int i = 0; i < 256; ++i) {
        printf("%d ", randomSub[i]);
    } 
    printf("\n");

    //Generate random shift number;
    randomShift = rand() % 8;
    printf("Random Shift: %d\n", randomShift);

    //Generate cipher key
    printf("Key: ");
    for(int i = 0; i < 32; ++i) {
        key[i] = rand()%256;
        printf("%d ", key[i]);
    }
    printf("\n");

    //Get the size of file to encrypt
    fp = fopen(inputFile, "rb");
    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("File size: %d\n", fileSize);
    
    //Allocate memory for input text buffer and encrypted text buffer
    unsigned char* plainText = (unsigned char*)malloc(sizeof(unsigned char) * fileSize);
    unsigned char* encryptedText = (unsigned char*)malloc(sizeof(unsigned char) * fileSize);

    //Read the input text from file
    fread(plainText, sizeof(*plainText), fileSize, fp);
    fclose(fp);

    //Stage 1: Sub each byte from the input text using the random sub table
    for(unsigned int i = 0; i < fileSize; ++i) {
        encryptedText[i] = randomSub[plainText[i]];
    }

    //Stage 2: Shift bytes in groups of 4 bytes
    for(unsigned int i = 0; i < fileSize; ++i) {
    	encryptedText[i] = (encryptedText[i] << randomShift) | (encryptedText[i] >> (8 - randomShift));
    }

    //Stage 3: XOR with the cipher key
    for(unsigned int i = 0; i < fileSize; ++i) {
    	encryptedText[i] = encryptedText[i] ^ key[(i%32)];
    }

    //Write the encrypted text to a file
    fp = fopen("encrypted", "wb");
    fwrite(encryptedText, sizeof(*encryptedText), fileSize, fp);
    fclose(fp);

    //Write the cipher table and key to a file
    fp = fopen("cipher", "wb");
    fwrite(&(randomSub[0]), sizeof(unsigned char), 256, fp);
    fwrite(&randomShift, sizeof(unsigned char), 1, fp);
    fwrite(&(key[0]), sizeof(unsigned char), 32, fp);
    fclose(fp);

    //Free heap memory
    free(plainText);
    free(encryptedText);
}

void decrypt(char* ciphertext, char* cipher) {
    //Variables for file operations
    FILE* fp;
    unsigned int fileSize;

    //Variables for sub table, random shift of bytes and key
    unsigned char randomSub[256];
    unsigned char invRandomSub[256];
    unsigned char randomShift;
    unsigned char key[32];

    //Read the random sub table, random shift of bytes and key from cipher file
    fp = fopen(cipher, "rb");
    fread(&(randomSub[0]), sizeof(unsigned char), 256, fp);
    fread(&randomShift, sizeof(unsigned char), 1, fp);
    fread(&(key[0]), sizeof(unsigned char), 32, fp);
    fclose(fp);

    //Create an inverse random sub table for decryption
    for(int i = 0; i < 256; ++i) {
        invRandomSub[randomSub[i]] = i;
    } 
 
    //Get the size of file to decrypt
    fp = fopen(ciphertext, "rb");
    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("File size: %d\n", fileSize);
 
    //Allocate memory for encrypted text buffer and decrypted text buffer
    unsigned char* encryptedText = (unsigned char*)malloc(sizeof(unsigned char) * fileSize);
    unsigned char* decryptedText = (unsigned char*)malloc(sizeof(unsigned char) * fileSize);

    //Read the text from the encrypted file
    fread(encryptedText, sizeof(*encryptedText), fileSize, fp);
    fclose(fp);

    //Stage 1: XOR with key
    for(unsigned int i = 0; i < fileSize; ++i) {
    	decryptedText[i] = encryptedText[i] ^ key[(i%32)];
    }

    //Stage 2: Shift bytes back
    for(unsigned int i = 0; i < fileSize; ++i) {
    	decryptedText[i] = (decryptedText[i] >> randomShift) | (decryptedText[i] << (8 - randomShift));
    }

    //Stage 3: Sub each byte from the encrypted text using the inverse sub table
    for(unsigned int i = 0; i < fileSize; ++i) {
        decryptedText[i] = invRandomSub[decryptedText[i]];
    }

    //Write decrypted text to a file
    fp = fopen("decrypted", "wb");
    fwrite(decryptedText, sizeof(*decryptedText), fileSize, fp);
    fclose(fp);

    //Free dynamically allocated memory
    free(encryptedText);
    free(decryptedText);
}

int main(int argc, char* argv[]) {
    //Check arguments supplied and call the corresponding functions
    if(argc == 2) {
        printf("Encryption Mode\n");
        encrypt(argv[1]);
    } else if(argc == 3) {
        printf("Decryption Mode\n");
        decrypt(argv[1], argv[2]);
    } else {
        printf("Invalid number of arguments\n");
        printf("Encryption Usage: ./a.out plaintext\n");
        printf("Decryption Usage: ./a.out encryptedtext cipher\n");
    }
    return 0;
}
