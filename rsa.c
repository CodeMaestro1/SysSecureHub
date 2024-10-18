#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <time.h>

#define STR_BASE 16

char filepath_input[100] = "files/input_file.txt";

int read_file(char* filepath, char** message) {
    FILE *fptr;
    long fileSize;
    fptr = fopen(filepath, "r");

    if (fptr == NULL) {
        printf("fptr error\n");
        return 1;
    }
    fseek(fptr, 0, SEEK_END);
    fileSize = ftell(fptr); // get file size
    fseek(fptr, 0, SEEK_SET); // reset cursor to start

    *message = (char *)malloc(fileSize + 1);
    if (message == NULL) {
        printf("message malloc error\n");
        fclose(fptr);
        return 1;
    }
    fread(*message, 1, fileSize, fptr);
    (*message)[fileSize] = '\0'; // Null-terminate the string
    fclose(fptr);

    return 0;
}

void generate_random_prime(mpz_t prime, unsigned long int bit_length, gmp_randstate_t state) {
    // mpz_t seed;
    // mpz_init(seed);
    // mpz_set_ui(seed, (unsigned long int)time(NULL));
    // printf("%s\n\n", mpz_get_str(NULL, 0, seed));
    // scanf("%d", seed);
    // unsigned long int seed = (unsigned long int) time(NULL);

    // // random state
    // gmp_randstate_t state; // random state for generating random nums
    // gmp_randinit_mt(state); // Mersenne Twister algorithm because I saw it online 
    // gmp_randseed_ui(state, seed); // more randomness based on time 
    // gmp_randseed(state, seed);
    

    // rand_num place-holder init 
    mpz_t rand_num;
    mpz_init(rand_num); 

    // generate random number
    mpz_urandomb(rand_num, state, bit_length); 
    // find next prime
    mpz_nextprime(prime, rand_num); 
    // check if prime is of desired length in bits 
    while (mpz_sizeinbase(prime, 2) != bit_length) {
        // repeat until (hopefully) true  
        mpz_urandomb(rand_num, state, bit_length);
        mpz_nextprime(prime, rand_num);
    }

    // clear vars
    mpz_clear(rand_num);
    // gmp_randclear(state);
}

void generateRSAKeyPair(mpz_t n, mpz_t e, mpz_t d, unsigned long int key_length) {
    mpz_t p, q;
    mpz_inits(p, q, NULL);

    // init state here because gmp_randseed_ui or gmp_randseed refused to work
    gmp_randstate_t state; // random state for generating random nums
    gmp_randinit_mt(state); // Mersenne Twister algorithm because I saw it online 

    // generate random primes for p, q 
    while(mpz_cmp(p, q) == 0) { // repeat if p == q 
        generate_random_prime(p, key_length/2, state);
        generate_random_prime(q, key_length/2, state);
        printf("p:\n%s\n\n", mpz_get_str(NULL, 0, p));
        printf("q:\n%s\n\n", mpz_get_str(NULL, 0, q));
    }

    // n = p * q
    mpz_mul(n, p, q);

    // lambda(n) = (p-1) * (q-1) process 
    mpz_t p_1, q_1, lambda;
    mpz_inits(p_1, q_1, lambda, NULL);

    // p_1 = p - 1
    mpz_sub_ui(p_1, p, 1);
    // q_1 = 1 - 1
    mpz_sub_ui(q_1, q, 1);
    // lambda(n) = (p-1) * (q-1)
    mpz_mul(lambda, p_1, q_1);

    // Use common public key (e) 65537
    // assumes length > 17 (?)
    // for large lengths condition: e % lambda(n) != 0 is likely true 
    mpz_set_ui(e, 65537);

    // check if it's co-prime of lambda
    mpz_t gcd;
    mpz_init(gcd);
    while (mpz_gcd(gcd, e, lambda), mpz_cmp_ui(gcd, 1) != 0) {
        mpz_nextprime(e, e); // check next prime (hopefully it doesn't get too big for large key_lengths)
    }

    // find private key (d)
    mpz_invert(d, e, lambda) == 0;

    // clear vars
    gmp_randclear(state);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(p_1);
    mpz_clear(q_1);
    mpz_clear(lambda);
    mpz_clear(gcd);
}

void string_to_mpz(mpz_t result, const char *str) {
    char hex_str[1024] = {0};
    // Convert the string to hexadecimal representation
    for (int i = 0; i < strlen(str); i++) {
        sprintf(hex_str + i * 2, "%02x", (unsigned char)str[i]);
    }
    // Set the mpz_t from the hex string
    mpz_set_str(result, hex_str, 16);
}

void mpz_to_string(char *result, mpz_t mpz_val) {
    char *hex_str = mpz_get_str(NULL, 16, mpz_val);
    size_t hex_len = strlen(hex_str);
    
    // Convert the hex string back to ASCII characters
    for (size_t i = 0; i < hex_len; i += 2) {
        unsigned int byte;
        sscanf(hex_str + i, "%02x", &byte);
        result[i / 2] = (char)byte;
    }
    result[hex_len / 2] = '\0';

    free(hex_str);
}

void encrypt(mpz_t encrypted, char** message, mpz_t e, mpz_t n) {
    // init mpz_message (needed to use mpz_powm)
    mpz_t mpz_message;
    mpz_init(mpz_message);

    // convert string to mpz
    string_to_mpz(mpz_message, *message);
    // mpz_set_str(mpz_message, *message, STR_BASE);

    // encryption process
    mpz_powm(encrypted, mpz_message, e, n);

    // clear vars
    mpz_clear(mpz_message);
}

void decrypt(mpz_t original, mpz_t encrypted, mpz_t d, mpz_t n) {
    mpz_powm(original, encrypted, d, n);
}

int main() {
    // init vars
    mpz_t n, e, d, ciphertext, decrypted_message;
    mpz_inits(n, e, d, ciphertext, decrypted_message, NULL);
    unsigned long int key_length = 1024;

    // get rsa key pair
    generateRSAKeyPair(n, e, d, key_length);
    printf("n: %s\n\ne: %s\n\nd: %s\n\n", mpz_get_str(NULL, 0, n), mpz_get_str(NULL, 0, e), mpz_get_str(NULL, 0, d));

    char *message = NULL;
    if (read_file(filepath_input, &message) != 0) {
        return -1;
    }
    printf("Original message:\n%s\n\n", message);

    // init vars
    mpz_t encrypted, decrypted;
    mpz_inits(encrypted, decrypted, NULL);
    encrypt(encrypted, &message, e, n);
    decrypt(decrypted, encrypted, d, n);

    // The decrypted message must be equal to the original
    printf("Encrypted: %s\n\n", mpz_get_str(NULL, STR_BASE, encrypted));
    printf("Decrypted:\n%s\n\n", mpz_get_str(NULL, STR_BASE, decrypted));

    char decrypted_msg[1024];
    mpz_to_string(decrypted_msg, decrypted);
    printf("Decrypted2:\n%s\n\n", decrypted_msg);

    // clear vars
    free(message);
    mpz_clear(encrypted);
    mpz_clear(decrypted);

    // prime check
    // mpz_t p;
    // mpz_init(p);
    // generate_random_prime(p, key_length/2);
    // printf("%s", mpz_get_str(NULL, 0, p));
    // size_t bit_length2 = mpz_sizeinbase(p, 2);
    // printf("Bit length of the number is %Zd bits\n", bit_length2);

    return 0;
}
