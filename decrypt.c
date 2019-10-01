#include "decrypt.h"

/*
 * Function:  read_key
 * --------------------
 * This function takes in the cipherkey file and reads the sub table,
 * the random shift and the key. It also creates the inverse sub
 * table needed for decryption
 * --------------------
 * filename: cipherkey file
 * invRandomSub: pointer to store the inverese sub table
 * randomShift: pointer to store cyclical byte shift
 * key: pointer to store the 32 byte key
 *
 * returns: 0 -> function pass, 1-> function fail
 */
int read_key(char* filename, unsigned char* invRandomSub, short* randomShift, unsigned char* key) {
    FILE* fp;    //file pointer
    unsigned char randomSub[CHAR_MAX];    //array to read the sub table used for encryption
    int i, fileSize;

    fp = fopen(filename, "rb");
    if(fp == NULL) {
        fprintf(stderr, "File open failed. Check if cipherkey file exists!\n");
        return 1;
    }

    //Check correct size of key file
    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if(fileSize != KEY_FILE_SIZE) {
        fprintf(stderr, "Invalid cipherkey file. Make sure its the correct key!\n");
        return 1;
    }

    //Read the random sub table from cipher file
    if(fread(&randomSub[0], sizeof(unsigned char), CHAR_MAX, fp) != CHAR_MAX) {
        fprintf(stderr, "fread failed while trying to read the sub table.\n");
        return 1;
    }

    //Read the random shift of bytes from cipher file
    if(fread(randomShift, sizeof(short), 1, fp) != 1) {
        fprintf(stderr, "fread failed while trying to read the shift.\n");
        return 1;
    }

    //Read the key from cipher file
    if(fread(key, sizeof(unsigned char), KEY_SIZE, fp) != KEY_SIZE) {
        fprintf(stderr, "fread failed while trying to read the key.\n");
        return 1;
    }

    fclose(fp);

    //Create an inverse random sub table for decryption
    for(i = 0; i < CHAR_MAX; ++i) {
        invRandomSub[randomSub[i]] = i;
    }

    return 0;
}


/*
 * Function:  decrypt
 * --------------------
 * This is the basic decryption algorithm that is used
 * to recover the plaintext from the ciphertext.
 * This algorithm is basically the reverse of the encryption.
 *
 * This function calls the read_key to read the key
 * structures from the cipherkey file.
 *
 * The decrypted file follows the naming convention
 * inputFilename_recovered.extension
 *
 * There are 3 stages when decryption:
 * 1) Use the 32-byte cipher key and XOR each set of 32 bytes
 * from the incoming file with this key
 * 2) Use the random number and right shift each byte
 * cyclically in that many times.
 * 3) Use the inverse of the random substitute table and sub
 * each 8-bit character to recover the original 8-bit character.
 * --------------------
 * ciphertext: file to decrypt
 * cipherkey: key file to the ciphertext
 */
void decrypt(char* ciphertext, char* cipherkey) {
    //Variables for file operations
    FILE *inFilePointer, *outFilePointer;
    long fileSize;

	char* outFile;    //variable for file naming

    //Variables for sub table, random shift of bytes and key
    unsigned char invRandomSub[CHAR_MAX];
    short randomShift;
    unsigned char key[KEY_SIZE];

	//Read key and seperate into parts
	if(read_key(cipherkey, &invRandomSub[0], &randomShift, &key[0]) == 1) {
		return;
	}
 
    //Open input ciphertext file
    inFilePointer = fopen(ciphertext, "rb");
    if(inFilePointer == NULL) {
    	fprintf(stderr, "File open failed. Check if ciphertext file exists!\n");
    	return;
    }

    //Get the size of file to encrypt
    fseek(inFilePointer, 0, SEEK_END);
    fileSize = ftell(inFilePointer);
    fseek(inFilePointer, 0, SEEK_SET);
    printf("File size: %ld bytes\n", fileSize);

    if(fileSize == 0) {
    	fprintf(stderr, "Invalid file size. Atleast one byte needed to encrypt!\n");
    	fclose(inFilePointer);
    	return;
    }

    //Allocate memory for output file name
    outFile = (char*)malloc(sizeof(char) * (strlen(ciphertext) + 11));
    if(outFile == NULL) {
    	fprintf(stderr, "malloc failed!\n");
    	return;
    }

    //Create name for the output recovered file
    char* extensionPos = strrchr(ciphertext, '.');
	int extensionIndex = strlen(ciphertext) - strlen(extensionPos);
	strncpy(outFile, ciphertext, extensionIndex);
	strcpy(outFile+extensionIndex, "_recovered");
	strcpy(outFile+extensionIndex+10, extensionPos);

    //Open the output file
    outFilePointer = fopen(outFile, "wb");
    if(outFilePointer == NULL) {
    	fprintf(stderr, "File open failed while trying to write the recovered text.\n");
    	return;
    }

    //Free dynamically allocated memory for filename
	free(outFile);

    //Process the file (at most 200MiB at once)
    while(fileSize > 0) {
    	//Find the size of block to decrypt
    	int allocSize = (fileSize > MAX_BUF_SIZE) ? MAX_BUF_SIZE : fileSize;

    	//Allocate space for the text buffer
    	unsigned char* textArray = (unsigned char*)malloc(sizeof(*textArray) * allocSize);
        if(textArray == NULL) {
        	fprintf(stderr, "malloc failed!\n");
        	return;
        }

        //Read the input from the file
        if(fread(textArray, sizeof(*textArray), allocSize, inFilePointer) != allocSize) {
        	fprintf(stderr, "fread failed while trying to read the ciphertext.\n");
        	return;
        }

        int i;
        for(i = 0; i < allocSize; ++i) {
        	//Stage 1: XOR with key
        	textArray[i] = textArray[i] ^ key[(i%32)];

        	//Stage 2: Shift bytes back
        	textArray[i] = (textArray[i] >> randomShift) | (textArray[i] << (8 - randomShift));

        	//Stage 3: Sub each byte from the encrypted text using the inverse sub table
        	textArray[i] = invRandomSub[textArray[i]];
        }

        //Write the ciphertext block to output the file
        if(fwrite(textArray, sizeof(*textArray), allocSize, outFilePointer) != allocSize) {
        	fprintf(stderr, "fwrite failed while trying to write the recovered text.\n");
        	return;
        }

        //Free heap memory
        free(textArray);

        fileSize -= allocSize;
    }

    //Close files
    fclose(inFilePointer);
    fclose(outFilePointer);
}
