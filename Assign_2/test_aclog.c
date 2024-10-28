#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#define OWNERSHIP_PERMISSIONS 0700  // Owner: read, write, execute
#define GROUP_PERMISSIONS 0070      // Group: read, write, execute
#define OTHERS_PERMISSIONS 0007     // Others: read, write, execute
#define PUBLIC_PERMISSIONS 0777     // Owner, Group, Others: read, write, execute

void set_permissions(const char *filename, int permissions) {
    if (chmod(filename, permissions) == -1) {
        perror("Error changing permissions");
    }
}

void simulate_user_access(const char *filename, int permission_type) {
    set_permissions(filename, permission_type);
    
    for (int i = 0; i < 10; i++) {
        FILE *file = NULL;
        char buffer[100] = "Test data";
        
        if (i < 2 || (i >= 8 && i < 10)) {
            file = fopen(filename, "r");
            if (file == NULL) {
                perror("Error opening file for reading");
                continue;
            }
            fread(buffer, 1, sizeof(buffer), file);
        } 
        else if (i >= 2 && i < 5) {
            file = fopen(filename, "w");
            if (file == NULL) {
                perror("Error opening file for writing");
                continue;
            }
            fwrite(buffer, 1, strlen(buffer), file);
        } 
        else if (i >= 5 && i < 8) {
            file = fopen(filename, "a");
            if (file == NULL) {
                perror("Error opening file for appending");
                continue;
            }
            fwrite(buffer, 1, strlen(buffer), file);
        }
        
        if (file != NULL) {
            fclose(file);
        }
    }
}

int main() {

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

			int permissions = 	(i < 2) ? PUBLIC_PERMISSIONS :
                        	(i < 5) ? OWNERSHIP_PERMISSIONS :
                        	(i < 8) ? GROUP_PERMISSIONS : OTHERS_PERMISSIONS;

            simulate_user_access(filenames[i], permissions);
        }
    }
	return 0;
    }