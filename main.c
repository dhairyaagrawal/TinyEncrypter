#include <stdio.h>

#include "includes/encrypt.h"
#include "includes/decrypt.h"

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
        printf("Encryption Usage: ./program plaintext\n");
        printf("Decryption Usage: ./program ciphertext cipherkey\n");
    }
    return 0;
}
