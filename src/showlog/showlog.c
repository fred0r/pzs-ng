/*
  showlog v1.0 by neoxed
  Displays the latest entries in the dirlog and nukelog
  in an easy-to-parse format for scripts.
  2005-01-01 - psxc:
               modded to be included in pzs-ng
               fixed some warnings.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "glstructs.h"

/* Default values */
#define GLCONF "/etc/glftpd.conf"
static char rootpath[MAXPATHLEN+1] = "/glftpd";
static char datapath[MAXPATHLEN+1] = "/ftp-data";
static char ipckey[11] = "0x000DEAD";
static int max_results = 10;
static int match_full = 0;
static int search_mode = 0;

enum {
	NO_ACTION = 1,
	SHOW_NEWDIRS,
	SHOW_NUKES,
	SHOW_UNNUKES
};

void load_sysconfig(const char *config_file);
void show_newdirs(const char *pattern);
void show_nukes(const ushort status, const char *pattern);
char *trim(char *str);
void usage(const char *binary);
int wildcasecmp(const char *wild, const char *string);
int get_glversion(int);

int main(int argc, char *argv[])
{
	char *config_file = GLCONF;
	char *pattern = NULL;
	int action = NO_ACTION, c;
	int free_config = 0;

	if (argc < 2) {
		usage(argv[0]);
	}

	/* Parse command line arguments */
	/* Usage: [-h] [-f] [-s] [-m <max #>] [-p <pattern>] [-r <glconf>] <-l, -n, or -u> */

	opterr = 0;
	while((c = getopt(argc, argv, "hfsm:p:r:lnu")) != -1) {
		switch(c) {
			case 'f':
				match_full = 1;
				break;
			case 'l':
				action = SHOW_NEWDIRS;
				break;
			case 'm':
				if ((max_results = atoi(optarg)) < 1) {
					max_results = 1;
				}
				break;
			case 'n':
				action = SHOW_NUKES;
				break;
			case 'p':
				pattern = strdup(optarg);
				break;
			case 'u':
				action = SHOW_UNNUKES;
				break;
			case 'r':
				config_file = strdup(optarg);
				free_config = 1;
				break;
			case 's':
				search_mode = 1;
				break;
			default:
				usage(argv[0]);
		}
	}

	load_sysconfig(config_file);

	switch(action) {
		case SHOW_NEWDIRS:
			show_newdirs(pattern);
			break;
		case SHOW_NUKES:
			show_nukes(0, pattern);
			break;
		case SHOW_UNNUKES:
			show_nukes(1, pattern);
			break;
		default:
			usage(argv[0]);
			break;
	}

	if (free_config && config_file != NULL) {
		free(config_file);
	}
	if (pattern != NULL) {
		free(pattern);
	}

	return 0;
}


/* load_sysconfig - Loads data from glftpd configuration file. */
void load_sysconfig(const char *config_file)
{
	FILE *fp;
	char lvalue[64];
	char rvalue[MAXPATHLEN];
	char work_buff[MAXPATHLEN];
	int x, y;

	if ((fp = fopen(config_file, "r")) == NULL) {
		fprintf(stderr, "Unable to open the config file (%s), using default values.\n", config_file);
		return;
	}

	while(fgets(work_buff, sizeof(work_buff), fp) != NULL) {
		/* Clip out comments */
		for(x = 0; x < (signed)(int)strlen(work_buff); x++) {
			if (work_buff[x] == '#') {
				work_buff[x] = '\0';
			}
		}

		/* Trim */
		trim(work_buff);

		/* Clear out old values */
		memset(lvalue, 0, sizeof(lvalue));
		memset(rvalue, 0, sizeof(rvalue));

		/* Parse lvalue */
		y = 0;
		for(x = 0; x < (signed)(int)strlen(work_buff) && work_buff[x] != ' '; x++) {
			if (isprint(work_buff[x])) {
				lvalue[y++] = work_buff[x];
			}
		}

		/* Parse rvalue */
		y = 0;
		x++;
		for (; x < (signed)(int)strlen(work_buff); x++) {
			if (isprint(work_buff[x])) {
				rvalue[y++] = work_buff[x];
			}
		}

		if (strcasecmp(lvalue, "datapath") == 0) {
			strncpy(datapath, rvalue, sizeof(datapath) - 1);
			datapath[sizeof(datapath) - 1] = 0;
		}
		if (strcasecmp(lvalue, "rootpath") == 0) {
			strncpy(rootpath, rvalue, sizeof(rootpath) - 1);
			rootpath[sizeof(rootpath) - 1] = 0;
		}
		if (strcasecmp(lvalue, "ipc_key") == 0) {
			strncpy(ipckey, rvalue, sizeof(ipckey) - 1);
			ipckey[sizeof(ipckey) - 1] = 0;
		}
	}

	fclose(fp);
	return;
}

int get_glversion (int glversion)
{
	int shmid = -1;
	struct shmid_ds shmval;

	if ((shmid = shmget((key_t) strtoll(ipckey, NULL, 16), 0, 0)) == -1)
		perror("shmget");

	if (shmctl(shmid, IPC_STAT, &shmval) == -1)
		perror("shmctl");

	if (shmval.shm_segsz%sizeof(struct ONLINE_GL132))
		glversion = 200;
	else
		glversion = 132;

	return glversion;
}

/* trim - Trim whitespace from a string. */
char *trim(char *str)
{
	char *ibuf, *obuf;

	if (str) {
		for (ibuf = obuf = str; *ibuf;) {
			while(*ibuf && isspace(*ibuf)) {
				ibuf++;
			}
			if (*ibuf && (obuf != str)) {
				*(obuf++) = ' ';
			}
			while(*ibuf && !isspace(*ibuf)) {
				*(obuf++) = *(ibuf++);
			}
		}
		*obuf = '\0';
	}
	return (str);
}


/* show_newdirs - Display the latest specified entries in the dirlog. */
void show_newdirs(const char *pattern)
{
	FILE *fp;
	char dirlog_path[MAXPATHLEN+1];
	snprintf(dirlog_path, sizeof(dirlog_path), "%s%s/logs/dirlog", rootpath, datapath);

    if ((fp = fopen(dirlog_path, "rb")) == NULL) {
        printf("Failed to open dirlog (%s): %s\n", dirlog_path, strerror(errno));
        exit(1);
    } else {
	struct dirlog132 buffer132;
	struct dirlog200 buffer200;
    	char *p;
	int i = 0, glversion = 0;

	glversion = get_glversion(glversion);

    	fseek(fp, 0L, SEEK_END);
    	while(i < max_results) {
			if (glversion == 132) {
				if (fseek(fp, -(sizeof(struct dirlog132)), SEEK_CUR) != 0)
					break;
				if (fread(&buffer132, sizeof(struct dirlog132), 1, fp) < 1)
					break;
				else
					fseek(fp, -(sizeof(struct dirlog132)), SEEK_CUR);

				/* Only display newdirs unless search_mode is specified (-s) */
				if (!search_mode && buffer132.status != 0)
					continue;

				if (pattern != NULL) {
					/* Pointer to the base of the directory path */
					if (!match_full && (p = strrchr(buffer132.dirname, '/')) != NULL)
						*p++;
					else
						p = buffer132.dirname;

					if (!wildcasecmp(pattern, p))
						continue;
				}
				/* Format: status|uptime|uploader|group|files|kilobytes|dirname */
				printf("%d|%u|%d|%d|%d|%ld|",
					buffer132.status, (unsigned int)buffer132.uptime, buffer132.uploader, buffer132.group,
					buffer132.files, buffer132.bytes/1024);
				puts(buffer132.dirname);
			} else {
				if (fseek(fp, -(sizeof(struct dirlog200)), SEEK_CUR) != 0)
					break;
				if (fread(&buffer200, sizeof(struct dirlog200), 1, fp) < 1)
					break;
				else
					fseek(fp, -(sizeof(struct dirlog200)), SEEK_CUR);

				/* Only display newdirs unless search_mode is specified (-s) */
				if (!search_mode && buffer200.status != 0)
					continue;

				if (pattern != NULL) {
					/* Pointer to the base of the directory path */
					if (!match_full && (p = strrchr(buffer200.dirname, '/')) != NULL)
						*p++;
					else
						p = buffer200.dirname;
					if (!wildcasecmp(pattern, p))
						continue;
				}

				/* Format: status|uptime|uploader|group|files|kilobytes|dirname */
				printf("%d|%u|%d|%d|%d|%lld|",
					buffer200.status, (unsigned int)buffer200.uptime, buffer200.uploader, buffer200.group,
					buffer200.files, buffer200.bytes/1024);
				puts(buffer200.dirname);
			}

			i++;
    	}
    	fclose(fp);
    }
    return;
}


/* show_nukes - Display the latest specified entries in the nukelog. */
void show_nukes(const ushort status, const char *pattern)
{
	FILE *fp;
	char nukelog_path[MAXPATHLEN+1];
	snprintf(nukelog_path, sizeof(nukelog_path), "%s%s/logs/nukelog", rootpath, datapath);

    if ((fp = fopen(nukelog_path, "rb")) == NULL) {
        printf("Failed to open nukelog (%s): %s\n", nukelog_path, strerror(errno));
        exit(1);
    } else {
    	struct nukelog buffer;
    	char *p;
		int i = 0;

    	fseek(fp, 0L, SEEK_END);
    	while(i < max_results) {
			if (fseek(fp, -(sizeof(struct nukelog)), SEEK_CUR) != 0) {
				break;
			}
			if (fread(&buffer, sizeof(struct nukelog), 1, fp) < 1) {
				break;
			} else {
				fseek(fp, -(sizeof(struct nukelog)), SEEK_CUR);
			}

			/* Only display nukes/unnukes unless search_mode is specified (-s) */
			if (!search_mode && buffer.status != status) {
				continue;
			}

			if (pattern != NULL) {
				/* Pointer to the base of the directory path */
				if (!match_full && (p = strrchr(buffer.dirname, '/')) != NULL) {
					*p++;
				} else {
					p = buffer.dirname;
				}
				if (!wildcasecmp(pattern, p)) {
					continue;
				}
			}

			/* Format: status|nuketime|nuker|unnuker|nukee|multiplier|reason|kilobytes|dirname */
			printf("%d|%u|%s|%s|%s|%d|%s|%.0f|",
				buffer.status, (unsigned int)buffer.nuketime, buffer.nuker, buffer.unnuker,
				buffer.nukee, buffer.mult, buffer.reason, buffer.bytes*1024.0);
			puts(buffer.dirname);
			i++;
    	}
    	fclose(fp);
    }
    return;
}


/* usage - Display the various parameters for showlog */
void usage(const char *binary)
{
	printf("Usage: %s [-h] [-f] [-s] [-m <max #>] [-p <pattern>] [-r <glconf>] <-l, -n, or -u>\n\n", binary);
	printf("Options:\n");
	printf("  -h  This help screen.\n");
	printf("  -f  Match the full path rather than the base name (default off).\n");
	printf("  -m  Maximum number of results to display (default %d).\n", max_results);
	printf("  -p  Display only the matching entries, you may use wildcards (?,*).\n");
	printf("  -r  Path to the glftpd configuration file (default " GLCONF ").\n");
	printf("  -s  Search mode, display all entries disregarding their status (new, deleted, nuked, etc.).\n\n");
	printf("Required Parameters:\n");
	printf("  -l  Display the latest dirlog entries.\n");
	printf("  -n  Display the latest nukes from the nukelog.\n");
	printf("  -u  Display the latest unnukes from the nukelog.\n\n");
	printf("  **  Only specify one required parameter.\n");
	exit(1);
}


/* http://www.codeproject.com/string/wildcmp.asp
 * modded by neoxed for case insensitivity
 */
int wildcasecmp(const char *wild, const char *string)
{
	const char *cp = 0, *mp = 0;

	while(*string && *wild != '*') {
		if (*wild != '?' && tolower(*wild) != tolower(*string)) {
			return 0;
		}
		wild++;
		string++;
	}

	while(*string) {
		if (*wild == '*') {
			if (!*++wild) {
				return 1;
			}
			mp = wild;
			cp = string+1;
		} else if (*wild == '?' || tolower(*wild) == tolower(*string)) {
			wild++;
			string++;
		} else {
			wild = mp;
			string = cp++;
		}
	}

	while(*wild == '*') {
		wild++;
	}
	return !*wild;
}
