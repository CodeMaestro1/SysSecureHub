#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

int main(int argc, char *argv[]) {
    char *filename = "test_file.txt";
    char *message = "default text";

    int opt;
    while ((opt = getopt(argc, argv, "f:m:")) != -1) {
        switch (opt) {
            case 'f':
                filename = optarg;
                break;
            case 'm':
                message = optarg;
                break;
            default:
            	exit(1);
        }
    }

    printf("|||%s - %s|||\n", message, filename);

    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }
    fwrite(message, sizeof(char), strlen(message), file);
    fwrite(message, sizeof(char), strlen(message), file);
    
    fclose(file);

    return 0;
}