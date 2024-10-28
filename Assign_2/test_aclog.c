#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#define GENERAL_PERMISSIONS 0777          // Full permissions for owner, group, and others
#define OWNER_GROUP_PERMISSIONS 0660      // Owner and group have read/write access
#define OTHERS_PERMISSIONS 0007           // Only others have execute permissions
#define BUFFER_SIZE 100

// Set file permissions and handle errors
void set_permissions(const char *filename, int permissions) {
    if (chmod(filename, permissions) == -1) {
        fprintf(stderr, "Error changing permissions for %s: %s\n", filename, strerror(errno));
    }
}

// Open and handle file operations with read or write modes
void handle_file_access(const char *filename, const char *mode) {
    FILE *file = fopen(filename, mode);
    if (!file) {
        fprintf(stderr, "Error opening file %s with mode %s: %s\n", filename, mode, strerror(errno));
        return;
    }

    char buffer[BUFFER_SIZE] = "Test data";  // Test data to write
    if (strcmp(mode, "r") == 0) {
        memset(buffer, 0, sizeof(buffer));  // Clear buffer before reading
        fread(buffer, 1, sizeof(buffer) - 1, file);
    } else {
        fwrite(buffer, 1, strlen(buffer), file);
    }

    fclose(file);
}

// Simulate user access based on iteration index
void simulate_user_access(const char *filename, int permission_type, int mode_index) {
    set_permissions(filename, permission_type);

    if (mode_index == 0) {
        handle_file_access(filename, "r");
    } else if (mode_index == 1) {
        handle_file_access(filename, "w");
    }
}

int main() {
    const char *filenames[10] = { 
        "file_0", "file_1", "file_2", "file_3", "file_4",
        "file_5", "file_6", "file_7", "file_8", "file_9"
    };

    // Create files and assign appropriate permissions
    for (int i = 0; i < 10; i++) {
        FILE *file = fopen(filenames[i], "w+");
        if (!file) {
            fprintf(stderr, "Failed to create %s: %s\n", filenames[i], strerror(errno));
            continue;
        }
        
        fwrite(filenames[i], strlen(filenames[i]), 1, file);
        fclose(file);

        int permissions = (i < 3) ? GENERAL_PERMISSIONS :
                          (i <= 6) ? OWNER_GROUP_PERMISSIONS : OTHERS_PERMISSIONS;

        simulate_user_access(filenames[i], permissions, i % 2);  // Alternate between read and write
    }

    return 0;
}
