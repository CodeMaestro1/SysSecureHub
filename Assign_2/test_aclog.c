#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#define OWNERSHIP_PERMISSIONS 0700  // Owner: read, write, execute
#define GROUP_PERMISSIONS 0070      // Group: read, write, execute
#define OTHERS_PERMISSIONS 0007     // Others: read, write, execute
#define PUBLIC_PERMISSIONS 0777     // Owner, Group, Others: read, write, execute

void set_permissions(char *filename) 
{
    if (chmod(filename, PUBLIC_PERMISSIONS) == -1) {
        printf("Error changing permissions for %s: %s\n", filename, strerror(errno));
    }
}

void simulate_user_access(char *filename){
    for(int i = 0; i < 10; i++){
        while (i < 2) {
            FILE *file = fopen(filename, "r");
            if (file == NULL) {
                printf("Error opening file for reading\n");
            } else {
                char buffer[100];
                fread(buffer, 1, 100, file);
                fclose(file);
            }
            i++;
        }

        while (i >= 2 && i < 5) {
            FILE *file = fopen(filename, "w");
            if (file == NULL) {
                printf("Error opening file for writing\n");
            } else {
                char buffer[100] = "Test data";
                fwrite(buffer, 1, strlen(buffer), file);
                fclose(file);
            }
            i++;
        }

        while (i >= 5 && i < 8) {
            FILE *file = fopen(filename, "a");
            if (file == NULL) {
                printf("Error opening file for appending\n");
            } else {
                char buffer[100] = "Test data";
                fwrite(buffer, 1, strlen(buffer), file);
                fclose(file);
            }
            i++;
        }

        while (i >= 8 && i < 10) {
            FILE *file = fopen(filename, "r");
            if (file == NULL) {
                printf("Error opening file for reading\n");
            } else {
                char buffer[100];
                fread(buffer, 1, 100, file);
                fclose(file);
            }
            i++;
        }
    }
}

int main() 
{
    int i;
    size_t bytes;
    FILE *file;
    char filenames[10][7] = {"file_0", "file_1", 
            "file_2", "file_3", "file_4",
            "file_5", "file_6", "file_7",         
            "file_8", "file_9"};

    // Create files and set permissions
    for (i = 0; i < 10; i++) {
        file = fopen(filenames[i], "w+");
        if (file == NULL) {
            printf("fopen error for %s\n", filenames[i]);
        } else {
            bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
            fclose(file);
            set_permissions(filenames[i]);
        }
    }

    // Simulate user access
    for (i = 0; i < 10; i++) {
        simulate_user_access(filenames[i]);
    }

    return 0;
}