#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "pcg_basic.h"

#define CHAR_MAX 256
#define CHAR_BITS 8
#define KEY_SIZE 32
#define MAX_BUF_SIZE 209715200

//Encryption functions
void shuffle(unsigned char* array, int size);
void generate_key(unsigned char* randomSub, short* randomShift, unsigned char* key);
void write_key(char* filename, unsigned char* randomSub, short* randomShift, unsigned char* key);
void encrypt(char* inputFile);