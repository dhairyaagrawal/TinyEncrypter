#include "encrypt.h"

/*
 * Function:  shuffle
 * --------------------
 * This function takes an unsigned char array of
 * size n and randomly shuffles it so that the order
 * of elements in the incoming array is randomized.
 *
 * This is used to create a lookup table to substitute
 * a plaintext character to a ciphertext character.
 * --------------------
 * array: unsigned char array to shuffle
 * n: size of array
 */
void shuffle(unsigned char* array, int n) {
    int i;
    if(n > 1) {
        for(i = 0; i < n; ++i) {
        	//Get a random index in the array and swap elements
            int j = (int)pcg32_boundedrand(CHAR_MAX);
            unsigned char temp = array[j];
            array[j] = array[i];
            array[i] = temp;
        }
    }
}


/*
 * Function:  generate_key
 * --------------------
 * This function takes generates the random substitution table,
 * the random shift number and the key to be used in encryption.
 * random function from the pcg library is used as it is a
 * statistically better function.
 * --------------------
 * randomSub: pointer to store the sub table
 * randomShift: pointer to store cyclical byte shift
 * key: pointer to store the 32 byte key
 */
void generate_key(unsigned char* randomSub, short* randomShift, unsigned char* key) {
    int i;

	//Random seed function for pcg library - uses time and virtual addresses
    pcg32_srandom(time(NULL) ^ (intptr_t)&printf, (intptr_t)&i);

    //Generate the byte substitution table
    for(i = 0; i < CHAR_MAX; ++i) {
        randomSub[i] = i;
    }
    shuffle(randomSub, CHAR_MAX);    //shuffle the table for confusion

    //Generate random shift number between 0 and 7
    *randomShift = (short)pcg32_boundedrand(CHAR_BITS);

    //Generate cipher key
    for(i = 0; i < KEY_SIZE; ++i) {
        key[i] = (unsigned char)pcg32_boundedrand(CHAR_MAX);
	}
}


/*
 * Function:  write_key
 * --------------------
 * This function takes in the parts of the cipher key, namely
 * the random substitution table, the random shift and the
 * key, and writes it out to a cipherkey file.
 *
 * The output file uses the name of the input file  and follows
 * the naming convention inputFilename_cipherkey.extension
 * --------------------
 * filename: input file used for encryption
 * randomSub: random substitution table (as an array of unsigned char)
 * randomShift: cyclical byte shift
 * key: 32 byte key used to XOR
 */
void write_key(char* filename, unsigned char* randomSub, short* randomShift, unsigned char* key) {
    char* outFile;    //varibale for file naming
    FILE* fp;    //file pointer

    outFile = (char*)malloc(sizeof(*filename) * (strlen(filename) + 11));
    if(outFile == NULL) {
    	fprintf(stderr, "malloc failed!\n");
    	return;
    }

    //Create name for cipherkey file
    char* extensionPos = strrchr(filename, '.');
    int extensionIndex = strlen(filename) - strlen(extensionPos);
    strncpy(outFile, filename, extensionIndex);
    strcpy(outFile+extensionIndex, "_cipherkey");
    strcpy(outFile+extensionIndex+10, extensionPos);

    //Open cipherkey file for writing
    fp = fopen(outFile, "wb");
    if(fp == NULL) {
    	fprintf(stderr, "File open failed while trying to write the cipherkey.\n");
    	return;
    }

    //Free memory allocated for filename
    free(outFile);

    //Write the sub table to the cipherkey file
    if(fwrite(randomSub, sizeof(unsigned char), CHAR_MAX, fp) != CHAR_MAX) {
    	fprintf(stderr, "fwrite failed while trying to write the sub table.\n");
    	return;
    }

    //Write the random shift to the cipherkey file
    if(fwrite(randomShift, sizeof(short), 1, fp) != 1) {
    	fprintf(stderr, "fwrite failed while trying to write the shift.\n");
    	return;
    }

    //Write the key to the cipherkey file
    if(fwrite(key, sizeof(unsigned char), KEY_SIZE, fp) != KEY_SIZE) {
    	fprintf(stderr, "fwrite failed while trying to write the key.\n");
    	return;
    }

    //Close file
    fclose(fp);
}


/*
 * Function:  encrypt
 * --------------------
 * This is the basic encryption algorithm that is used
 * to create the ciphertext from the plaintext.
 * This algorithm is basically a substitution cipher (a hybrid
 * stream/block cipher) that can handle a file of any size.
 *
 * This function calls the generate_key to generate the key
 * structures and write_key function to write the cipher key
 * to a file.
 *
 * The encrypted file follows the naming convention
 * inputFilename_ciphertext.extension
 *
 * There are 3 stages when encrypting:
 * 1) Generate a random substitute table and sub each 8-bit
 * character to some other 8-bit character.
 * 2) Generate a random number between 0-7 and left shift each
 * byte cyclically that many times.
 * 3) Generate a 32-byte key and XOR each set of 32 bytes
 * from the incoming file with this key for added confusion.
 * --------------------
 * inputFile: file to encrypt
 */
void encrypt(char* inputFile) {
    //Variables for file operations
    FILE *inFilePointer, *outFilePointer;
    long fileSize;

    char* outFile;    //variable for file naming

    //Variables for random sub table, random shift of bytes and key
    unsigned char randomSub[CHAR_MAX];
    short randomShift;
    unsigned char key[KEY_SIZE];

    //Generate the key structures
    generate_key(&randomSub[0], &randomShift, &key[0]);

    //Open input file
    inFilePointer = fopen(inputFile, "rb");
    if(inFilePointer == NULL) {
    	fprintf(stderr, "File open failed. Check if input file exists!\n");
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

    //Memory for output filename
    outFile = (char*)malloc(sizeof(char) * (strlen(inputFile) + 12));
    if(outFile == NULL) {
    	fprintf(stderr, "malloc failed!\n");
    	return;
    }

    //Create name for the output ciphertext file
    char* extensionPos = strrchr(inputFile, '.');
    int extensionIndex = strlen(inputFile) - strlen(extensionPos);
    strncpy(outFile, inputFile, extensionIndex);
    strcpy(outFile+extensionIndex, "_ciphertext");
    strcpy(outFile+extensionIndex+11, extensionPos);

    //Open the output file
    outFilePointer = fopen(outFile, "wb");
    if(outFilePointer == NULL) {
    	fprintf(stderr, "File open failed while trying to write the ciphertext.\n");
    	return;
    }

    //Free heap allocated for output filename
    free(outFile);
    
    //Process the file (at most 200MiB at once)
    while(fileSize > 0) {
    	//Find the size of block to encrypt
    	int allocSize = (fileSize > MAX_BUF_SIZE) ? MAX_BUF_SIZE : fileSize;

    	//Allocate space for the text buffer
    	unsigned char* textArray = (unsigned char*)malloc(sizeof(*textArray) * allocSize);
        if(textArray == NULL) {
            fprintf(stderr, "malloc failed!\n");
            return;
        }

        //Read the input from the file
        if(fread(textArray, sizeof(*textArray), allocSize, inFilePointer) != allocSize) {
            fprintf(stderr, "fread failed while trying to read the plaintext.\n");
            return;
        }

        int i;
        for(i = 0; i < allocSize; ++i) {
            //Stage 1: Sub each byte from the input text using the random sub table
            textArray[i] = randomSub[textArray[i]];

            //Stage 2: Shift bytes
            textArray[i] = (textArray[i] << randomShift) | (textArray[i] >> (8 - randomShift));

            //Stage 3: XOR with the cipher key
            textArray[i] = textArray[i] ^ key[(i%32)];
        }

        //Write the ciphertext block to output the file
        if(fwrite(textArray, sizeof(*textArray), allocSize, outFilePointer) != allocSize) {
            fprintf(stderr, "fwrite failed while trying to write the ciphertext.\n");
            return;
        }

        //Free heap memory
        free(textArray);

        fileSize -= allocSize;
    }

    //Close files
    fclose(inFilePointer);
    fclose(outFilePointer);

    //Write key to file
    write_key(inputFile, &randomSub[0], &randomShift, &key[0]);
}
