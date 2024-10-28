#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> //install the required package
#include <errno.h>
#include <limits.h>

#define DATETIME_SIZE 50
#define BUFFER_SIZE 1024
#define LOG_FILE_PATH "file_logging.log"

void check() {
	int temp;
	printf("\nCheck\n");
	scanf("%d", &temp);
}

void get_time_and_date(char* date_var, char* time_var) {
	time_t t;
	time(&t); // current datetime

	struct tm *tmp = gmtime(&t); // utc time 

	strftime(date_var, DATETIME_SIZE, "%x", tmp);
	strftime(time_var, DATETIME_SIZE, "%I:%M%p", tmp);
}

FILE* normal_fopen(const char* path, const char* mode) {
	FILE* original_fopen_ret;
	FILE* (*original_fopen)(const char*, const char*);
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	return original_fopen_ret;
}

char* get_filepath(FILE* file) {
    int fd;
    char procpath[PATH_MAX];
    char* filepath = (char*)malloc(PATH_MAX); 

    if (!filepath) {
    	printf("Error malloc\n");
    	fclose(file);
    	return NULL;
    }

    // find file descriptor in cur proc 
    fd = fileno(file);
    if (fd < 0) {
    	printf("Error getting filepath from file pointer\n");
    	free(filepath);
    	fclose(file);
    	return NULL;
    }

    // concat fd to proc file path 
    snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", fd);

    if (!realpath(procpath, filepath)) {
    	printf("Error couldn't find realpath\n");
    	free(filepath);
        fclose(file);
        return NULL;
    }
    // printf("- %s-\n", filepath); // test

    return filepath;
}

char* get_file_fingerprint(const char *path) {
	/* inits */ 
	size_t bytes;
	char buffer[BUFFER_SIZE]; // buffer
	unsigned int md_len; // stores hash length 
	EVP_MD_CTX *mdctx; // stores hash context
	unsigned char md_value[EVP_MAX_MD_SIZE]; // stores hash

	/* normal fopen file rb */ 
	FILE* file = normal_fopen(path, "rb");
	if (file == NULL) {
    	printf("failed to read bytes of %s\n", path);
	    return NULL;
    }

    /* Hashing process */
	mdctx = EVP_MD_CTX_new(); // init new context
	const EVP_MD *md = EVP_md5(); // use EVP md5 function

	EVP_DigestInit_ex(mdctx, md, NULL);  // init digest type 

	while ( (bytes = fread(buffer, 1, BUFFER_SIZE, file)) != 0 ) { // reads in values from buffer containing file pointer
		EVP_DigestUpdate(mdctx, buffer, bytes); // add buffer to hash context
	}

	EVP_DigestFinal_ex(mdctx, md_value, &md_len); // finalize hash context

	/* put the hash in the file */
	char* fingerprint;
	fingerprint = (char*)malloc(2*md_len + 1);
	if (!fingerprint) {
		printf("Error malloc\n");
		fclose(file);
		EVP_MD_CTX_free(mdctx);
		return NULL;
	}

	for (size_t i = 0; i < md_len; i++) { // loops through the hash 
		sprintf(&fingerprint[i*2], "%02x", md_value[i]); 
	}
	fingerprint[2*md_len] = '\0'; // add '\0' char

	EVP_MD_CTX_free(mdctx);
	fclose(file);
	return fingerprint;
}

FILE *fopen(const char *path, const char *mode) 
{
	printf("In my fopen\n");
	int file_exists = (access(path, F_OK) == 0); // get file_exists before opening file 
	
	/* normal fopen file */
	FILE* original_fopen_ret = normal_fopen(path, mode);
	
	int action_denied = 0;
	if (!original_fopen_ret) {
		if (errno == EACCES) {
			action_denied = 1;
			printf("EEEEEEEEE");
		} else { // other error
			printf("Error opening file %s", path);
			return NULL;
		}
	}

	/* Get logging info */
	int uid = getuid(); // get uid 

	// date & time
	char date_var[DATETIME_SIZE];
	char time_var[DATETIME_SIZE];
	get_time_and_date(date_var, time_var);
	
	// get access_type
	int access_type = file_exists ? 1 : 0;

	// fingerprint
	char* abs_path = NULL;
	char* fingerprint = NULL;
	if (original_fopen_ret) { 
		if ( !(abs_path = get_filepath(original_fopen_ret)) ) { // do this to get absolute path
			printf("LOG ERROR: Error getting filepath\n");
			return original_fopen_ret; // return actual when log fails (?)
		}
		if ( !(fingerprint = get_file_fingerprint(abs_path)) ) {
			printf("LOG ERROR: Error getting fingerprint\n");
			free(abs_path);
			return original_fopen_ret; // return actual when log fails (?)
		}
	} else {
		abs_path = malloc(PATH_MAX);
		if (!abs_path) {
			printf("LOG ERROR: malloc error\n");
			return original_fopen_ret;
		}
		if (!realpath(path, abs_path)) {
			printf("LOG ERROR: Error getting filepath\n");
			free(abs_path);
			return original_fopen_ret;
		}		
		fingerprint = malloc(2);
		if (!fingerprint) {
			printf("LOG ERROR: malloc error\n");
			return original_fopen_ret;
		}		
		fingerprint[0] = '-';
		fingerprint[1] = '\0';
	}	

	FILE* log_file;
	log_file = normal_fopen(LOG_FILE_PATH, "a"); // append to log
	if (!log_file) {
		printf("LOG ERROR: Error opening %s", LOG_FILE_PATH);
		free(abs_path);
		free(fingerprint);
		return original_fopen_ret; // return actual when log fails (?)
	}
	
	fprintf(log_file, "%d %s %s %s %d %d %s\n", uid, abs_path, date_var, time_var, access_type, action_denied, fingerprint);
	
	free(abs_path);
	free(fingerprint);
	fclose(log_file);	
	return original_fopen_ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	printf("In my fwrite\n");

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	// flush buffer for hashing consistancy 
	fflush(stream);
	
	/* Get logging info */
	int uid = getuid(); // get uid 

	// date & time
	char date_var[DATETIME_SIZE];
	char time_var[DATETIME_SIZE];
	get_time_and_date(date_var, time_var);
	
	// get access_type
	int access_type = 2;

	// check if user denied 
	int action_denied = (original_fwrite_ret < size*nmemb); // once user has "w" fp, is there no privilige issue? (TODO) 

	// fingerprint
	char* fingerprint = NULL;
	char* abs_path = NULL;
	if (!original_fwrite_ret) {
		printf("Error writing to file\n");
		return -1; // normal fwrite normally crashes before this but hey 
	}
	if ( !(abs_path = get_filepath(stream)) ) { // do this to get absolute path
		printf("LOG ERROR: Error getting filepath\n");
		return original_fwrite_ret; // return actual when log fails (?)
	}
	if ( !(fingerprint = get_file_fingerprint(abs_path)) ) {
		printf("LOG ERROR: Error getting fingerprint\n");
		free(abs_path);
		return original_fwrite_ret; // return actual when log fails (?)
	}

	FILE* log_file;
	log_file = normal_fopen(LOG_FILE_PATH, "a"); // append to log 
	if (!log_file) {
		printf("LOG ERROR: Error opening %s", LOG_FILE_PATH);
		free(abs_path);
		free(fingerprint);
		return original_fwrite_ret; // return actual when log fails (?)
	}
	fprintf(log_file, "%d %s %s %s %d %d %s\n", uid, abs_path, date_var, time_var, access_type, action_denied, fingerprint);

	free(abs_path);
	free(fingerprint);
	fclose(log_file);	
	return original_fwrite_ret;
}


