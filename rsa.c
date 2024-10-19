#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <time.h>

#define STR_BASE 16

char filepath_input[100] = "files/input_file.txt";

char nibbleToChar(unsigned char nibble) {
    if (nibble < 10) {
        return '0' + nibble; // Convert 0-9 to '0'-'9'
    } else {
        return 'a' + (nibble - 10); // Convert 10-15 to 'a'-'f'
    }
}

int read_file_hex(char* filepath, char** message, unsigned long int key_length, long cur_cursor) {
    FILE *fptr;
    long fileSize;
    fptr = fopen(filepath, "rb");

    if (fptr == NULL) {
        printf("fptr error\n");
        return 1;
    }
    fseek(fptr, 0, SEEK_END);
    fileSize = ftell(fptr); // get file size
    fseek(fptr, cur_cursor, SEEK_SET); // reset cursor to start

    long  new_cursor;
    long remaining_len = fileSize - cur_cursor;
    if (remaining_len > (key_length/8)-1) {
        fileSize = (key_length/8)-1;
        new_cursor = cur_cursor + fileSize;
    } else {
        fileSize = remaining_len;
        new_cursor = -2; // eof
    }

    *message = (char *)malloc(2 * fileSize + 1); // each byte has 2 hex chars
    if(message == NULL) {
        printf("message malloc error\n");
        fclose(fptr);
        return -1;
    }
    char* buffer = malloc(fileSize * sizeof(unsigned char));
    if (buffer == NULL) { // Check if memory allocation was successful
        printf("buffer malloc error\n");
        free(message);
        fclose(fptr);
        return -1;
    }

    // Read the file into the buffer
    fread(buffer, 1, fileSize, fptr);
    
    // seperate byte to 2 nibbles for each char
    int count = 0;
    for (long i = 0; i < fileSize; i++) {
        (*message)[count++] = nibbleToChar(buffer[i] >> 4); //XXXX---- -> XXXX0000
        (*message)[count++] = nibbleToChar(buffer[i] & 0x0F); //----XXXX -> XXXX0000
    }
    (*message)[2*fileSize] = '\0'; // Null-terminate the string
    fclose(fptr);
    free(buffer);

    return new_cursor;
}

char* hex_stream_to_ascii(char *hexString) {
    long hexLength = strlen(hexString); // Get the length of the hex string

    // Each pair of hex digits corresponds to one ASCII character
    long asciiLength = hexLength / 2;
    char *asciiString = malloc(asciiLength + 1); // +1 for null terminator
    if (asciiString == NULL) {
        printf("ascii string malloc error");
        return NULL;
    }

    for (long i = 0; i < asciiLength; i++) {
        unsigned int byteValue;
        // use sscanf because it provides hexadecimal integer support (painful)
        // gets first 2 chars at pointer and stores them in byteValue 
        sscanf(&hexString[i*2], "%2x", &byteValue); 
        asciiString[i] = (char)byteValue;
    }
    asciiString[asciiLength] = '\0';

    return asciiString;
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

void encrypt(mpz_t encrypted, char** message, mpz_t e, mpz_t n) {
    // init mpz_message (needed to use mpz_powm)
    mpz_t mpz_message;
    mpz_init(mpz_message);

    // convert string to mpz
    // string_to_mpz(mpz_message, *message);
    mpz_set_str(mpz_message, *message, STR_BASE);

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

    /* init vars */
    // message vars (in between)
    char *message = NULL;
    char *full_message = NULL;
    mpz_t encrypted, decrypted;
    char* decrypted_msg;

    // cursor
    long cur_cursor = 0;

    // full_message len
    long total_length = 0;

    // init full_message
    full_message = malloc(1);
    if (full_message == NULL) {
        printf("full_message malloc error");
        return -1;
    }
    full_message[0] = '\0';

    // loop to encrypt/decrypt file every ~key_length bits
    while (cur_cursor != -2) {
        mpz_inits(encrypted, decrypted, NULL);

        cur_cursor = read_file_hex(filepath_input, &message, key_length, cur_cursor);
        printf("Original message:\n%s\n\n", message);

        // malloc error when reading file
        if (cur_cursor == -1) {
            return -1;
        }

        /* RSA Process */
        encrypt(encrypted, &message, e, n);

        decrypt(decrypted, encrypted, d, n);

        printf("Encrypted: %s\n\n", mpz_get_str(NULL, STR_BASE, encrypted));
        printf("Decrypted:\n%s\n\n", mpz_get_str(NULL, STR_BASE, decrypted));

        decrypted_msg = hex_stream_to_ascii(mpz_get_str(NULL, STR_BASE, decrypted));

        printf("Decrypted2:\n%s\n\n", decrypted_msg);

        total_length += strlen(decrypted_msg); // incr total_len
        full_message = realloc(full_message, total_length + 1); // realloc full_message
        if (full_message == NULL) {
            perror("full_message realloc error");
            free(decrypted_msg);
            return 1;
        }

        // Concatenate decrypted_msg to full_message
        strcat(full_message, decrypted_msg);

        // clear vars
        mpz_clear(encrypted);
        mpz_clear(decrypted);
        free(message);
        free(decrypted_msg);
        
        printf("--------------------------------------------\n");
    }
        
    printf("Full message:\n%s\n\n", full_message);

    // clear vars
    free(full_message);
    

    // prime check
    // mpz_t p;
    // mpz_init(p);
    // generate_random_prime(p, key_length/2);
    // printf("%s", mpz_get_str(NULL, 0, p));
    // size_t bit_length2 = mpz_sizeinbase(p, 2);
    // printf("Bit length of the number is %Zd bits\n", bit_length2);

    return 0;
}
