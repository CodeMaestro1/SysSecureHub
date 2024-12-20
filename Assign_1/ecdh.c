#include <stdio.h>
#include <sodium.h>
#include <getopt.h>

/* Define some globoal varialbes that we will need later*/
unsigned char alice_private_key[crypto_box_SECRETKEYBYTES]; 
unsigned char alice_public_key[crypto_box_PUBLICKEYBYTES]; 
unsigned char bob_private_key[crypto_box_SECRETKEYBYTES];
unsigned char bob_public_key[crypto_box_PUBLICKEYBYTES]; 
unsigned char alice_shared_secret[crypto_scalarmult_BYTES]; 
unsigned char bob_shared_secret[crypto_scalarmult_BYTES];

char *nameFile = NULL;
int alice_key_provided = 0;
int bob_key_provided = 0;

void int_to_byte_key(unsigned char *private_key, int number) {
    for (unsigned int i = 0; i < crypto_box_SECRETKEYBYTES; i++) {
        private_key[i] = (unsigned char)(number >> (i * 8));
    }
}

void handle_keys(unsigned char *private_key, unsigned char *public_key, int key_provided) {
    if (!key_provided) {
        crypto_box_keypair(public_key, private_key);
    } else {
        crypto_scalarmult_base(public_key, private_key);
    }
}

void print_menu(){
    printf("Usage: ecdh -o path [-a number] [-b number] [-h]\n");
    printf("Options:\n");
    printf(" -o path Path to output file\n");
    printf(" -a number. Alice's private key(optional)\n");
    printf(" -b number. Bob's private key(optional)\n");
    printf(" -h This help message\n");
}



void getArgs(int argc, char *argv[]) {
    char c;
    int o_provided = 0;
    
    while ((c = getopt(argc, argv, "o:a:b:h")) != -1) {
        switch (c) {
        case 'o':
            if (optarg == NULL || optarg[0] == '-') {
                fprintf(stderr, "Option -o requires a valid argument\n");
                exit(EXIT_FAILURE);
            }
            nameFile = optarg;
            o_provided = 1;
            break;
        case 'a':
            if (!o_provided) {
                fprintf(stderr, "Option -a requires -o to be specified\n");
                exit(EXIT_FAILURE);
            }
            if (optarg == NULL || optarg[0] == '-') {
                fprintf(stderr, "Option -a requires a valid argument\n");
                exit(EXIT_FAILURE);
            }
            int_to_byte_key(alice_private_key, atoi(optarg));
            alice_key_provided = 1;
            break;
        case 'b':
            if (!o_provided) {
                fprintf(stderr, "Option -b requires -o to be specified\n");
                exit(EXIT_FAILURE);
            }
            if (optarg == NULL || optarg[0] == '-') {
                fprintf(stderr, "Option -b requires a valid argument\n");
                exit(EXIT_FAILURE);
            }
            int_to_byte_key(bob_private_key, atoi(optarg));
            bob_key_provided = 1;
            break;
        case 'h':
            print_menu();
            break;
        default:
            fprintf(stderr, "Invalid option\n");
            break;
        }
    }
}

void file_handler(char *path) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file %s!\n", path);
        exit(EXIT_FAILURE);
    }

    fprintf(fp, "Alice's Public key:\n");
    char hex_alice_public_key[crypto_box_PUBLICKEYBYTES * 2 + 1];
    fputs(sodium_bin2hex(hex_alice_public_key, sizeof(hex_alice_public_key), alice_public_key, crypto_box_PUBLICKEYBYTES), fp);
    fprintf(fp, "\n");

    fprintf(fp, "Bob's Public key:\n");
    char hex_bob_public_key[crypto_box_PUBLICKEYBYTES * 2 + 1];
    fputs(sodium_bin2hex(hex_bob_public_key, sizeof(hex_bob_public_key), bob_public_key, crypto_box_PUBLICKEYBYTES), fp);
    fprintf(fp, "\n");

    fprintf(fp, "Shared Secret(Alice):\n");
    char hex_alice_shared_secret[crypto_scalarmult_BYTES * 2 + 1];
    fputs(sodium_bin2hex(hex_alice_shared_secret, sizeof(hex_alice_shared_secret), alice_shared_secret, crypto_scalarmult_BYTES), fp);
    fprintf(fp, "\n");

    fprintf(fp, "Shared Secret(Bob):\n");
    char hex_bob_shared_secret[crypto_scalarmult_BYTES * 2 + 1];
    fputs(sodium_bin2hex(hex_bob_shared_secret, sizeof(hex_bob_shared_secret), bob_shared_secret, crypto_scalarmult_BYTES), fp);
    fprintf(fp, "\n");

    if (sodium_memcmp(alice_shared_secret, bob_shared_secret, crypto_scalarmult_BYTES) == 0) {
        fprintf(fp, "Shared secrets match!\n");
    } else {
        fprintf(fp, "Shared secrets do not match\n");
    }

    fclose(fp);
}



/**
 * @brief Main function of the program.
 */
int main(int argc, char *argv[]) {
    // init sodium
    if (sodium_init() < 0) {
        fprintf(stderr, "Error initializing libsodium\n");
        return EXIT_FAILURE;
    } else {
    
    getArgs(argc, argv);
    handle_keys(alice_private_key, alice_public_key, alice_key_provided);
    handle_keys(bob_private_key, bob_public_key, bob_key_provided);


    /* Calculate shared secret for each side */
    
    if (crypto_scalarmult(alice_shared_secret, alice_private_key, bob_public_key) != 0) {
        printf("Error\n");
    }
    if (crypto_scalarmult(bob_shared_secret, bob_private_key, alice_public_key) != 0) {
        printf("Error\n");
    }

    //Everything is done, let's wrte the output to the file
    file_handler(nameFile);

    // Zero out sensitive data before freeing memory
    sodium_memzero(alice_private_key, crypto_box_SECRETKEYBYTES);
    sodium_memzero(alice_public_key, crypto_box_PUBLICKEYBYTES);
    sodium_memzero(bob_private_key, crypto_box_SECRETKEYBYTES);
    sodium_memzero(bob_public_key, crypto_box_PUBLICKEYBYTES);
    sodium_memzero(alice_shared_secret, crypto_scalarmult_BYTES);
    sodium_memzero(bob_shared_secret, crypto_scalarmult_BYTES);

    return EXIT_SUCCESS;

}
}
