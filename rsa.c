#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <time.h>

#define STR_BASE 16
#define PADDING_CHAR '1'

void check() {
    int temp = 0;
    printf("Check");
    scanf("%d", &temp);
}

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
    
    char* asciiString; 
    asciiString = (char *)malloc(asciiLength + 1); // +1 for '/0'

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

char* add_padding(char* str) {
    char* padded_str;

    padded_str = malloc(strlen(str) + 2);
    if (padded_str == NULL) {
        printf("padded_str malloc str");
        exit(1);
    }
    padded_str[0] = PADDING_CHAR;
    strcpy(padded_str + 1, str);
    free(str);
    return padded_str;
}

char* remove_padding(char* padded_str) {
    memmove(padded_str, padded_str + 1, strlen(padded_str));
    return padded_str;
}

void encrypt(mpz_t encrypted, char** message, mpz_t e, mpz_t n) {
    // init mpz_message (needed to use mpz_powm)
    mpz_t mpz_message;
    mpz_init(mpz_message);

    // convert string to mpz
    // string_to_mpz(mpz_message, *message);
    *message = add_padding(*message);
    mpz_set_str(mpz_message, *message, STR_BASE);

    // encryption process
    mpz_powm(encrypted, mpz_message, e, n);

    // clear vars
    mpz_clear(mpz_message);
}

void decrypt(char** decrypted_msg, mpz_t encrypted, mpz_t d, mpz_t n) {
    mpz_t decrypted;
    mpz_init(decrypted);

    mpz_powm(decrypted, encrypted, d, n);
    printf("Decrypted:\n%s\n\n", mpz_get_str(NULL, STR_BASE, decrypted));

    *decrypted_msg = remove_padding(mpz_get_str(NULL, STR_BASE, decrypted));

    *decrypted_msg = hex_stream_to_ascii(*decrypted_msg);

}

void save_keys(mpz_t n, mpz_t e, mpz_t d, unsigned long int key_length) {
    char public_filename[50];
    char private_filename[50];
    snprintf(public_filename, sizeof(public_filename), "public_%lu.key", key_length);
    snprintf(private_filename, sizeof(private_filename), "private_%lu.key", key_length);

    // Public key file
    FILE *public_file = fopen(public_filename, "w");
    if (public_file == NULL) {
        printf("Error opening public key file");
        return;
    }
    fprintf(public_file, "%s\n%s\n", mpz_get_str(NULL, 0, n), mpz_get_str(NULL, 0, e));
    fclose(public_file);

    // Private key file 
    FILE *private_file = fopen(private_filename, "w");
    if (private_file == NULL) {
        printf("Error opening private key file");
        return;
    }
    fprintf(private_file, "%s\n%s\n", mpz_get_str(NULL, 0, n), mpz_get_str(NULL, 0, d));
    fclose(private_file);
}

void get_key(char* key_filepath, mpz_t n, mpz_t key) {
    FILE *file = fopen(key_filepath, "r");
    if (file == NULL) {
        printf("Error opening key file");
        return;
    }

    char *n_str = NULL;
    char *key_str = NULL;
    long n_size = 0;
    long key_size = 0;

    // get keys
    if (getline(&n_str, &n_size, file) == -1) {
        printf("Error reading n from file");
        fclose(file);
        free(n_str);
        return;
    }

    if (getline(&key_str, &key_size, file) == -1) {
        printf("Error reading key from file");
        fclose(file);
        free(n_str);
        free(key_str);
        return;
    }

    n_str[strcspn(n_str, "\n")] = '\0';
    key_str[strcspn(key_str, "\n")] = '\0';

    mpz_set_str(n, n_str, 10);
    mpz_set_str(key, key_str, 10);    

    fclose(file);
    free(n_str);
    free(key_str);
}

void create_keys(unsigned long int key_length) {
    // init vars
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    // get rsa key pair
    generateRSAKeyPair(n, e, d, key_length);
    printf("n: %s\n\ne: %s\n\nd: %s\n\n", mpz_get_str(NULL, 0, n), mpz_get_str(NULL, 0, e), mpz_get_str(NULL, 0, d));

    save_keys(n, e, d, key_length);
}

int encryption_process(char* filepath_input, char* filepath_output, unsigned long int key_length, mpz_t n, mpz_t e) {
    /* init vars */
    // message vars (in between)
    char *message = NULL;
    char *full_message = NULL;
    mpz_t encrypted;

    // cursor
    long cur_cursor = 0;

    // open out file
    FILE *outfile = fopen(filepath_output, "w");
    if (outfile == NULL) {
        printf("Failed to open file");
        return -1;
    }

    // loop to encrypt/decrypt file every ~key_length bits
    while (cur_cursor != -2) {
        mpz_init(encrypted);

        cur_cursor = read_file_hex(filepath_input, &message, key_length, cur_cursor);
        printf("Original message:\n%s\n\n", message);

        // malloc error when reading file
        if (cur_cursor == -1) {
            return -1;
        }

        /* RSA Process */
        encrypt(encrypted, &message, e, n);

        printf("Encrypted: %s\n\n", mpz_get_str(NULL, STR_BASE, encrypted));

        fprintf(outfile, "%s\n", mpz_get_str(NULL, STR_BASE, encrypted));

        // clear vars
        mpz_clear(encrypted);
        free(message);
        
        printf("--------------------------------------------\n");
    }
    fclose(outfile);
}

int decryption_process(char* filepath_input, char* filepath_output, unsigned long int key_length, mpz_t n, mpz_t d) {
    /* init vars */
    // message vars (in between)
    char *full_message = NULL;
    mpz_t encrypted;
    char* decrypted_msg;
    // init encrypted str (for reading lines)
    char* encrypted_str = NULL;
    long temp = 0;

    // open in file
    FILE *infile = fopen(filepath_input, "r"); 
    if (infile == NULL) {
        printf("Failed to open file");
        return -1;
    }
    // open out file
    FILE *outfile = fopen(filepath_output, "w"); 
    if (outfile == NULL) {
        printf("Failed to open file");
        return -1;
    }

    // Read each line from the file using getline
    while (getline(&encrypted_str, &temp, infile) != -1) {
        mpz_init(encrypted);
        long enc_len = strlen(encrypted_str);
        // printf("\n==%s==\n", encrypted_str);
        if (enc_len > 0 && encrypted_str[enc_len - 1] == '\n') { // if might be redundant 
            encrypted_str[enc_len - 1] = '\0';  // replace '\n' with '\0'
        }
        // printf("\n==%s==\n", encrypted_str);

        // put line in mpz var
        mpz_set_str(encrypted, encrypted_str, STR_BASE);

        decrypt(&decrypted_msg, encrypted, d, n);

        printf("Decrypted2:\n%s\n\n", decrypted_msg);

        fprintf(outfile, "%s", decrypted_msg);

        // clear vars
        mpz_clear(encrypted);
        free(decrypted_msg);

        printf("--------------------------------------------\n");
    }
    fclose(infile);
    fclose(outfile);
}


int main() {
    char filepath_input[100] = "files/input_file.txt";
    char filepath_cipher[100] = "files/cipher_file.txt"; //temp for testing
    char filepath_output[100] = "files/output_file.txt";
    int key_length = 1024;

    create_keys(key_length);

    mpz_t n, e, d;
    get_key("public_1024.key", n, e);
    printf("Gotten:\nn: %s\n\ne: %s\n\n", mpz_get_str(NULL, 0, n), mpz_get_str(NULL, 0, e));

    get_key("private_1024.key", n, d);
    printf("Gotten:\nn: %s\n\nd: %s\n\n", mpz_get_str(NULL, 0, n), mpz_get_str(NULL, 0, d));

    int ret;

    ret = encryption_process(filepath_input, filepath_cipher, key_length, n, e);

    ret = decryption_process(filepath_cipher, filepath_output, key_length, n, d);

    return 0;
}
