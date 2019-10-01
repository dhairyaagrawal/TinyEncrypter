#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHAR_MAX 256
#define KEY_SIZE 32
#define MAX_BUF_SIZE 209715200
#define KEY_FILE_SIZE 290

//Decryption functions
int read_key(char* filename, unsigned char* invRandomSub, short* randomShift, unsigned char* key);
void decrypt(char* ciphertext, char* cipherkey);