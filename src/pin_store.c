#include "pin_store.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PIN_DB_MAX_LINE 4096

/* Ensure the PIN database is a secure, root-owned regular file. */
static int db_permissions_ok(int fd)
{
    struct stat st;

    /*
     * The PIN database must be a root-owned regular file with no group/other
     * permissions, to avoid tampering or hash disclosure.
     */
    if (fstat(fd, &st) != 0) {
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        return -1;
    }

    if (st.st_uid != 0) {
        return -1;
    }

    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return -1;
    }

    return 0;
}

/* Strip trailing whitespace from a buffer in place. */
static void trim_trailing_whitespace(char *s)
{
    size_t len = strlen(s);

    /* Remove newline and trailing spaces from a line read via fgets. */
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        --len;
    }
}

/* Consume remaining characters up to the next newline. */
static void discard_until_eol(FILE *fp)
{
    int ch;

    /* Drop the overflow tail when a DB line exceeds our fixed buffer. */
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
    }
}

/* Look up a user's PIN hash from the database file. */
int pin_store_lookup_hash(const char *db_path, const char *username, char **hash_out)
{
    FILE *fp;
    int fd;
    char line[PIN_DB_MAX_LINE];
    int result = 0;

    *hash_out = NULL;

    if (db_path == NULL || username == NULL || *username == '\0') {
        return -1;
    }

    fd = open(db_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }

    if (db_permissions_ok(fd) != 0) {
        close(fd);
        return -1;
    }

    fp = fdopen(fd, "re");
    if (fp == NULL) {
        close(fd);
        return -1;
    }

    /* Parse lines in the form: username:hash */
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *sep;
        char *user;
        char *hash;
        size_t len;

        len = strlen(line);
        if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
            discard_until_eol(fp);
            continue;
        }

        trim_trailing_whitespace(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        sep = strchr(line, ':');
        if (sep == NULL) {
            continue;
        }

        *sep = '\0';
        user = line;
        hash = sep + 1;

        if (strcmp(user, username) != 0) {
            continue;
        }

        if (*hash == '\0') {
            result = -1;
            break;
        }

        /* Copy out the hash so callers can safely close the file immediately. */
        *hash_out = strdup(hash);
        if (*hash_out == NULL) {
            result = -1;
        } else {
            result = 1;
        }
        break;
    }

    if (fclose(fp) != 0 && result == 0) {
        result = -1;
    }

    return result;
}
