#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <ctype.h> // for isxdigit()

#define STR_BASE 16
#define PADDING_CHAR '1'
#define TEST_MODE_OFF 0
#define TEST_MODE_ON 1
#define TESTING_PHRASE_REPEATS 2000

int test_mode = TEST_MODE_OFF; // global var for testing 

double get_time_difference(struct timeval start, struct timeval end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6; // s
}

long get_memory_usage(struct rusage usage) {
    return usage.ru_maxrss * 1024;  // bytes
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

    long new_cursor;
    long unsigned int remaining_len = fileSize - cur_cursor;
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

char* hex_stream_to_ascii(const char *hexString) {
    long hexLength = strlen(hexString);

    // Check if the hex string length is even
    if (hexLength % 2 != 0) {
        printf("Invalid hex string length\n");
        return NULL;
    }

    // Each pair of hex digits corresponds to one ASCII character
    long asciiLength = hexLength / 2;
    
    char* asciiString = (char *)malloc(asciiLength + 1); // +1 for '\0'
    if (asciiString == NULL) {
        printf("Memory allocation error\n");
        return NULL;
    }

    for (long i = 0; i < asciiLength; i++) {
        char hexByte[3] = { hexString[i*2], hexString[i*2 + 1], '\0' };
        
        // Check if the characters are valid hex digits
        if (!isxdigit(hexByte[0]) || !isxdigit(hexByte[1])) {
            printf("Invalid hex digit\n");
            free(asciiString);
            return NULL;
        }

        asciiString[i] = (char)strtol(hexByte, NULL, 16);
    }
    asciiString[asciiLength] = '\0';

    return asciiString;
}

void generate_random_prime(mpz_t prime, unsigned long int bit_length, gmp_randstate_t state) {
    mpz_t rand_num;
    mpz_init(rand_num);

    do {
        // Generate a random number of the specified bit length
        mpz_urandomb(rand_num, state, bit_length);
        // Find the next prime greater than the random number
        mpz_nextprime(prime, rand_num);
    } while (mpz_sizeinbase(prime, 2) != bit_length); // Repeat until the prime has the desired bit length

    // Clear the random number variable
    mpz_clear(rand_num);
}


void generateRSAKeyPair(mpz_t n, mpz_t e, mpz_t d, unsigned long int key_length) {
    mpz_t p, q;
    mpz_inits(p, q, NULL);

    // init state here
    gmp_randstate_t state; // random state for generating random nums
    gmp_randinit_mt(state);

    // generate random primes for p, q 
    while(mpz_cmp(p, q) == 0) { // repeat if p == q 
        generate_random_prime(p, key_length/2, state);
        generate_random_prime(q, key_length/2, state);

    }
    
    mpz_mul(n, p, q);// n = p * q

    // lambda(n) = (p-1) * (q-1) process 
    mpz_t p_1, q_1, lambda;
    mpz_inits(p_1, q_1, lambda, NULL);

    mpz_sub_ui(p_1, p, 1);// p_1 = p - 1
   
    mpz_sub_ui(q_1, q, 1); // q_1 = 1 - 1
    
    mpz_mul(lambda, p_1, q_1);// lambda(n) = (p-1) * (q-1)

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
    mpz_invert(d, e, lambda);

    // clear vars
    gmp_randclear(state);
    mpz_clears(p, q, p_1, q_1, lambda, gcd, NULL);
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

    // Ensure message conversion succeeds
    if (mpz_set_str(mpz_message, *message, STR_BASE) == -1) {
        printf("Error converting message to mpz\n");
        mpz_clear(mpz_message);
        return;
    }

    //mpz_set_str(mpz_message, *message, STR_BASE);

    // encryption process
    mpz_powm(encrypted, mpz_message, e, n);

    // clear vars
    mpz_clear(mpz_message);
}


void decrypt(char** decrypted_msg, mpz_t encrypted, mpz_t d, mpz_t n) {
    mpz_t decrypted;
    mpz_init(decrypted);

    mpz_powm(decrypted, encrypted, d, n);

    // Convert decrypted number to string
    char *decrypted_str = mpz_get_str(NULL, STR_BASE, decrypted);
    if (decrypted_str == NULL) {
        fprintf(stderr, "Error converting decrypted number to string\n");
        mpz_clear(decrypted);
        return;
    }

    // Remove padding and convert to ASCII
    char *unpadded_str = remove_padding(decrypted_str);
    if (unpadded_str == NULL) {
        fprintf(stderr, "Error removing padding\n");
        free(decrypted_str);
        mpz_clear(decrypted);
        return;
    }

    *decrypted_msg = hex_stream_to_ascii(unpadded_str);
    if (*decrypted_msg == NULL) {
        fprintf(stderr, "Error converting hex stream to ASCII\n");
        free(decrypted_str);
        free(unpadded_str);
        mpz_clear(decrypted);
        return;
    }

    // Free the allocated strings
    free(decrypted_str);
    if (unpadded_str != decrypted_str) {
        free(unpadded_str);
    }

    mpz_clear(decrypted);
}

void save_keys(mpz_t n, mpz_t e, mpz_t d, unsigned long int key_length) {
    char public_filename[50];
    char private_filename[50];
    if (test_mode == TEST_MODE_OFF) { // OFF
        snprintf(public_filename, sizeof(public_filename), "public_%lu.key", key_length);
        snprintf(private_filename, sizeof(private_filename), "private_%lu.key", key_length);
    } else { // ON
        snprintf(public_filename, sizeof(public_filename), "TESTING_public_%lu.key", key_length);
        snprintf(private_filename, sizeof(private_filename), "TESTING_private_%lu.key", key_length);
    }

    // Public key file
    FILE *public_file = fopen(public_filename, "w");
    if (public_file == NULL) {
        printf("Error opening public key file");
        return;
    }
    char *n_str = mpz_get_str(NULL, 0, n);
    char *e_str = mpz_get_str(NULL, 0, e);
    if (n_str == NULL || e_str == NULL) {
        printf("Error converting mpz_t to string");
        free(n_str);
        free(e_str);
        fclose(public_file);
        return;
    }
    fprintf(public_file, "%s\n%s\n", n_str, e_str);
    free(n_str);
    free(e_str);
    fclose(public_file);

    // Private key file 
    FILE *private_file = fopen(private_filename, "w");
    if (private_file == NULL) {
        printf("Error opening private key file");
        return;
    }
    n_str = mpz_get_str(NULL, 0, n);
    char *d_str = mpz_get_str(NULL, 0, d);
    if (n_str == NULL || d_str == NULL) {
        printf("Error converting mpz_t to string");
        free(n_str);
        free(d_str);
        fclose(private_file);
        return;
    }
    fprintf(private_file, "%s\n%s\n", n_str, d_str);
    free(n_str);
    free(d_str);
    fclose(private_file);
}

void get_key(char* key_filepath, mpz_t n, mpz_t key, long unsigned int* key_length) {
    const char* format_error = "The format of '%s' is not recognized.\n";
    int valid_format = 0;

    if (test_mode == TEST_MODE_OFF) {
        valid_format = (sscanf(key_filepath, "public_%lu.txt", key_length) == 1 ||
                        sscanf(key_filepath, "private_%lu.txt", key_length) == 1);
    } else {
        valid_format = (sscanf(key_filepath, "TESTING_public_%lu.txt", key_length) == 1 ||
                        sscanf(key_filepath, "TESTING_private_%lu.txt", key_length) == 1);
    }

    if (!valid_format) {
        printf(format_error, key_filepath);
        return;
    }

    FILE *file = fopen(key_filepath, "r");
    if (file == NULL) {
        printf("Error opening key file");
        return;
    }

    char *n_str = NULL;
    char *key_str = NULL;
    size_t n_size = 0;
    size_t key_size = 0;

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

    // remove newline char
    n_str[strcspn(n_str, "\n")] = '\0';
    key_str[strcspn(key_str, "\n")] = '\0';

    if (mpz_set_str(n, n_str, 10) != 0) {
        fprintf(stderr, "Error converting n_str to mpz_t\n");
        fclose(file);
        free(n_str);
        free(key_str);
        return;
    }

    if (mpz_set_str(key, key_str, 10) != 0) {
        fprintf(stderr, "Error converting key_str to mpz_t\n");
        fclose(file);
        free(n_str);
        free(key_str);
        return;
    }

    fclose(file);
    free(n_str);
    free(key_str);
}

void create_keys(unsigned long int key_length) {
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    // get rsa key pair
    generateRSAKeyPair(n, e, d, key_length);

    save_keys(n, e, d, key_length);

    mpz_clears(n, e, d, NULL);
}

int encryption_process(char* filepath_input, char* filepath_output, unsigned long int key_length, mpz_t n, mpz_t e) {
    /* init vars */
    // message vars (in between)
    char *message = NULL;
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

        // malloc error when reading file
        if (cur_cursor == -1) {
            return -1;
        }

        /* RSA Process */
        encrypt(encrypted, &message, e, n);

        
        char *encrypted_str = mpz_get_str(NULL, STR_BASE, encrypted);
        if (encrypted_str == NULL) {
            fprintf(stderr, "Error converting encrypted number to string\n");
            mpz_clear(encrypted);
            free(message);
            fclose(outfile);
            return -1;
        }
        fprintf(outfile, "%s\n", encrypted_str);
        

        // clear vars
        free(encrypted_str); // Free the allocated string
        mpz_clear(encrypted);
        free(message);
    }
    fclose(outfile);
    return 0;
}

int decryption_process(char* filepath_input, char* filepath_output, mpz_t n, mpz_t d) {
    /* init vars */
    mpz_t encrypted;
    char* decrypted_msg = NULL;
    char* encrypted_str = NULL;
    size_t temp = 0;

    // open in file
    FILE *infile = fopen(filepath_input, "r"); 
    if (infile == NULL) {
        perror("Failed to open input file");
        return -1;
    }

    // open out file
    FILE *outfile = fopen(filepath_output, "w"); 
    if (outfile == NULL) {
        perror("Failed to open output file");
        fclose(infile);
        return -1;
    }

    // Initialize mpz_t variable
    mpz_init(encrypted);

    // Read each line from the file using getline
    while (getline(&encrypted_str, &temp, infile) != -1) {
        long enc_len = strlen(encrypted_str);
        if (enc_len > 0 && encrypted_str[enc_len - 1] == '\n') {
            encrypted_str[enc_len - 1] = '\0';  // replace '\n' with '\0'
        }

        // Convert string to mpz_t
        if (mpz_set_str(encrypted, encrypted_str, STR_BASE) != 0) {
            fprintf(stderr, "Error converting string to mpz_t\n");
            free(encrypted_str);
            fclose(infile);
            fclose(outfile);
            mpz_clear(encrypted);
            return -1;
        }

        // Decrypt the message
        decrypt(&decrypted_msg, encrypted, d, n);

        // Write decrypted message to output file
        fprintf(outfile, "%s", decrypted_msg);

        // Free decrypted message
        free(decrypted_msg);
        decrypted_msg = NULL; // Reset pointer to avoid dangling pointer
    }

    // Clean up
    free(encrypted_str);
    fclose(infile);
    fclose(outfile);
    mpz_clear(encrypted);

    return 0;
}

void print_help() {
    printf("Usage: ./rsa_assign_1 [OPTIONS]\n");
    printf("Options:\n");
    printf("  -i path      Path to the input file\n");
    printf("  -o path      Path to the output file\n");
    printf("  -k path      Path to the key file\n");
    printf("  -g length    Perform RSA key-pair generation given a key length \"length\"\n");
    printf("  -d           Decrypt input and store results to output\n");
    printf("  -e           Encrypt input and store results to output\n");
    printf("  -a path      Analyze performance and store results to specified file\n");
    printf("  -h           Show this help message\n");
}

int analyze_args(int argc, char *argv[], char** input_path, char** output_path, char** key_path, unsigned long int* key_length, int* mode) {
    int option;

    while ((option = getopt(argc, argv, "i:o:k:g:deha:")) != -1) {
        switch (option) {
            case 'i':
                *input_path = optarg;
                break;
            case 'o':
                *output_path = optarg;
                break;
            case 'k':
                *key_path = optarg;
                break;
            case 'g':
                *key_length = (unsigned long int)atoi(optarg);
                *mode = 1; // Key generation mode
                break;
            case 'd':
                *mode = 3; // Decryption mode
                break;
            case 'e':
                *mode = 2; // Encryption mode
                break;
            case 'a':
                if (optarg == NULL) {
                    *output_path = "performance.txt";
                } else {
                    *output_path = optarg;
                }
                *mode = 4; // Performance analysis mode
                break;
            case 'h':
                print_help();
                break;
            default:
                printf("Invalid option\n");
                return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    char* input_path = NULL;
    char* output_path = NULL;
    char* key_path = NULL;
    unsigned long int key_length = 0;
    int mode = 0; // 1 generate keys, 2 encrypt, 3 decrypt, 4 analyze

    if (analyze_args(argc, argv, &input_path, &output_path, &key_path, &key_length, &mode) != 0) {
        return 1;
    }

    // Options:
    // 1. Generate Keys
    if (mode == 1) { // Gen keys
        if (key_length <= 0) {
            fprintf(stderr, "Invalid key length\n");
            return 1;
        }
        /* Generate Keys */
        create_keys(key_length);
        printf("Saved a random key pair of %lu bits.\n", key_length);
    // 2. Encryption    
    } else if (mode == 2) { 
        if (!input_path || !output_path || !key_path) {
            fprintf(stderr, "For encryption, -i, -o, and -k options are required.\n");
            return 1;
        }
        /* Encrypt */
        mpz_t n, e;
        mpz_inits(n, e, NULL);
        get_key(key_path, n, e, &key_length);
        encryption_process(input_path, output_path, key_length, n, e);
        mpz_clears(n, e, NULL);
        printf("Encrypted %s to %s using keys from %s.\n", input_path, output_path, key_path);
    // 3. Decryption
    } else if (mode == 3) { 
        if (!input_path || !output_path || !key_path) {
            fprintf(stderr, "For decryption, -i, -o, and -k options are required.\n");
            return 1;
        }
        /* Decrypt */
        mpz_t n, d;
        mpz_inits(n, d, NULL);
        get_key(key_path, n, d, &key_length);
        decryption_process(input_path, output_path, n, d);
        mpz_clears(n, d, NULL);
        printf("Decrypted %s to %s using keys from %s.\n", input_path, output_path, key_path);
    } 
    // 4. Performance analysis
    else if (mode == 4) { 
        if (!output_path) {
            fprintf(stderr, "For performance analysis, -a option is required.\n");
            return 1;
        }
        // test mode on 
        test_mode = TEST_MODE_ON;

        // temp files for data
        char temp_input_file[100] = "TESTING_input_file.txt";
        char temp_cipher_file[100] = "TESTING_cipher_file.txt";
        char temp_output_file[100] = "TESTING_output_file.txt";

        // add a bunch of info to temp TESTING_file_1.txt (input)
        char test[16] = "testing phrase\n"; // Add a newline for better readability
        FILE *file = fopen(temp_input_file, "w");
        if (file == NULL) {
            perror("Error opening file");
            return 1; 
        }
        for (int i = 0; i < TESTING_PHRASE_REPEATS; i++) {
            fprintf(file, "%s", test);
        }
        fclose(file);

        // open performance.txt file 
        FILE *perf_file = fopen(output_path, "w");
        if (perf_file == NULL) {
            perror("Error opening file");
            return 1; 
        }

        // key lengths array 
        int key_lengths[] = {1024, 2048, 4096};
        // init keys
        mpz_t n, e, d;
        // init measurement vars 
        // Encrypt
        struct timeval start, end;
        struct rusage usage_before, usage_after;

        // Peak usage at the START of this process 
        getrusage(RUSAGE_SELF, &usage_before);

        // Loop of diff key lengths
        printf("Measured for key lengths ");
        for (int i = 0; i < 3; i++) {
            mpz_inits(n, e, d, NULL); // reset keys 

            long unsigned int key_length = key_lengths[i];
            printf("%lu ", key_length);
            // create keys
            create_keys(key_length); 

            // temp key files
            char public_filename[100];
            char private_filename[100];
            snprintf(public_filename, sizeof(public_filename), "TESTING_public_%lu.key", key_length);
            snprintf(private_filename, sizeof(private_filename), "TESTING_private_%lu.key", key_length);

            // get keys n, e
            get_key(public_filename, n, e, &key_length);

            // encryption process
            gettimeofday(&start, NULL);
            encryption_process(temp_input_file, temp_cipher_file, key_length, n, e);
            gettimeofday(&end, NULL);
            getrusage(RUSAGE_SELF, &usage_after);

            mpz_clears(n, e, NULL);
            mpz_init(n);

            double encryption_time = get_time_difference(start, end);
            long encryption_memory = get_memory_usage(usage_after);// - get_memory_usage(usage_before);

            // get keys n, d
            get_key(private_filename, n, d, &key_length);

            // decryption process
            gettimeofday(&start, NULL);
            decryption_process(temp_cipher_file, temp_output_file, n, d);
            gettimeofday(&end, NULL);
            getrusage(RUSAGE_SELF, &usage_after);

            mpz_clears(n, d, NULL);

            double decryption_time = get_time_difference(start, end);
            long decryption_memory = get_memory_usage(usage_after); //- get_memory_usage(usage_before);

            // write measurements to file
            fprintf(perf_file, "Key Length: %ld bits\n", key_length);
            fprintf(perf_file, "Encryption Time: %.6fs\n", encryption_time);
            fprintf(perf_file, "Decryption Time: %.6fs\n", decryption_time);
            fprintf(perf_file, "Peak Memory Usage (Encryption): %ld Bytes\n", encryption_memory);
            fprintf(perf_file, "Peak Memory Usage (Decryption): %ld Bytes\n\n", decryption_memory);

            // delete temp files
            if (remove(public_filename) != 0) { printf("Error deleting %s", public_filename); }
            if (remove(private_filename) != 0) { printf("Error deleting %s", private_filename); }
        }
        if (remove(temp_input_file) != 0) { printf("Error deleting %s", temp_input_file); }
        if (remove(temp_cipher_file) != 0) { printf("Error deleting %s", temp_cipher_file); }
        if (remove(temp_output_file) != 0) { printf("Error deleting %s", temp_output_file); }
        printf("\n");
        test_mode = TEST_MODE_OFF;
        fclose(perf_file);
        
    }

    return 0;
}
