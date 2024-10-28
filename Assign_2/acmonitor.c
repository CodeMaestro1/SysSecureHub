#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#define DATETIME_SIZE 50
#define LOG_FILE_PATH "file_logging.log"
#define MAX_USERS 100
#define MAX_FILES 50
#define DENIED_ACCESS_LIMIT 5 
#define FINGERPRINT_MAX 200
#define PATH_MAX_LITE 300 // too much memory otherwise (dynamic meme allocation for each filepath is obviously the solution but nah)


void check() {
	int temp;
	printf("\nCheck\n");
	scanf("%d", &temp);
}


struct log_entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char file[PATH_MAX]; /* filename (string) */
	char fingerprint[FINGERPRINT_MAX]; /* file fingerprint */
};


void usage()
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


int get_next_entry(FILE *log, struct log_entry* entry) {
	char date_str[DATETIME_SIZE];
	char time_str[DATETIME_SIZE];

	if ( fscanf(log, "%d %s %s %s %d %d %s\n",
		&entry->uid, entry->file, date_str, time_str,
		&entry->access_type, &entry->action_denied, entry->fingerprint) != 7 ) {

		return -1;
	}

	// convert datetime from str to time_t
	struct tm tmp;
	strptime(date_str, "%x", &tmp);
	entry->date = timegm(&tmp);
	strptime(time_str, "%I:%M%p", &tmp);
	entry->time = timegm(&tmp);

	// entry->date = 0;
	// entry->time = 0;
	return 0;
}

int find_uid(int user_index[], int uid) {
	int i = 0;
	while (user_index[i] != -1 && i < MAX_USERS) {
		if (user_index[i] == uid) {
			return i;
		}
		i++;
	}
	return -1;
}

int is_new_file(char accessed_files[][PATH_MAX_LITE], char* filepath) {
	for (int i = 0; i < MAX_FILES; i++) {
		if (strcmp(accessed_files[i], filepath) == 0) {
			return 0;
		}
	}
	return 1;
}

void list_unauthorized_accesses(FILE *log)
{
	struct log_entry entry;

	int user_index[MAX_USERS] = {0};
	int denied_access_counts[MAX_USERS] = {0}; // these can be replaced with hashing but c
	int user_count = 0; // current user count 

	char accessed_files[MAX_USERS][MAX_FILES][PATH_MAX_LITE]; // accessed filepath array 
	int af_count[MAX_USERS] = {0}; // indexing - accessed files count

	// init user index
    for (int i = 0; i < MAX_USERS; i++) {
        user_index[i] = -1;
    }

	while (get_next_entry(log, &entry) == 0) {
		// printf("%d %s %d %d %d %d %s\n",
		// entry.uid, entry.file, entry.date, entry.time,
		// entry.access_type, entry.action_denied, entry.fingerprint);
		if (entry.action_denied == 1) {
			int uid = entry.uid;
			int uid_idx = find_uid(user_index, uid);

			if (uid_idx == -1) {
				if (uid_idx > MAX_USERS) {
					printf("Error reached MAX_USERS\n");
					return;
				}
				// add to user index
				user_index[user_count] = uid;
				uid_idx = user_count;
				user_count++;
			}

			if (is_new_file(accessed_files[uid_idx], entry.file)) {
				if (af_count[uid_idx] > MAX_FILES) {
					printf("Error reached MAX_FILES\n");
					return;
				}
				denied_access_counts[uid_idx]++;
				strcpy(accessed_files[uid_idx][af_count[uid_idx]], entry.file);
				af_count[uid_idx]++;
			}
		}
	}

	printf("Malicious users (limit = %d):\n", DENIED_ACCESS_LIMIT);
	for (int i = 0; i < user_count; i++) {
		if (denied_access_counts[i] > DENIED_ACCESS_LIMIT) {
			printf("User %d, with %d\n", user_index[i], denied_access_counts[i]);
		}
	}


	// // testing - all users
	// printf("All users:\n");
	// for (int i = 0; i < user_count; i++) {
	// 	printf("User %d, with %d\n", user_index[i], denied_access_counts[i]);
	// }

	return;
}


void list_file_modifications(FILE *log, char *file_to_scan)
{
	struct log_entry entry;
	int user_index[MAX_USERS] = {0};
	int modifications_counts[MAX_USERS] = {0};
	int user_count = 0;

	char last_fingerprint[FINGERPRINT_MAX] = {0};
	int modifications_count = 0;

	// init user index
    for (int i = 0; i < MAX_USERS; i++) {
        user_index[i] = -1;
    }

    // get abs path
	char* abs_path = realpath(file_to_scan, NULL);
    if (!abs_path) {
    	printf("Error couldn't find realpath\n");
        return;
    }
    printf("%s\n\n", abs_path);

	while (get_next_entry(log, &entry) == 0) {
		if (strcmp(entry.file, abs_path) == 0 && entry.action_denied == 0) { // perms denied count as non mods (?)
			// handle user
			int uid = entry.uid;
			int uid_idx = find_uid(user_index, uid);
			if (uid_idx == -1) {
				if (uid_idx > MAX_USERS) {
					printf("Error reached MAX_USERS\n");
					return;
				}
				// add to user index
				user_index[user_count] = uid;
				uid_idx = user_count;
				user_count++;
			}
			// check if mod happened 
			if (strcmp(last_fingerprint, entry.fingerprint) != 0 && entry.access_type == 2) { // counts creation as mod (?)
				strcpy(last_fingerprint, entry.fingerprint); // update last 
				modifications_counts[uid_idx]++;
				modifications_count++;
			}
		}
	}

	printf("File '%s' modification:\n", file_to_scan);
	for (int i = 0; i < user_count; i++) {
		if (modifications_counts[i] > 0) {
			printf("User %d, with %d\n", user_index[i], modifications_counts[i]);
		}
	}
	printf("Total modifications: %d\n", modifications_count);
	return;

}


int main(int argc, char *argv[])
{
	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen(LOG_FILE_PATH, "r");
	if (log == NULL) {
		printf("Error opening %s\n", LOG_FILE_PATH);
		return 1;
	}

	// list_unauthorized_accesses(log);

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
