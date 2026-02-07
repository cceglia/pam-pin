#include "pin_store.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PIN_DB_MAX_LINE 4096

static int db_permissions_ok(const char *db_path)
{
    struct stat st;

    if (stat(db_path, &st) != 0) {
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

static void trim_trailing_whitespace(char *s)
{
    size_t len = strlen(s);

    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        --len;
    }
}

static void discard_until_eol(FILE *fp)
{
    int ch;

    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
    }
}

int pin_store_lookup_hash(const char *db_path, const char *username, char **hash_out)
{
    FILE *fp;
    char line[PIN_DB_MAX_LINE];
    int result = 0;

    *hash_out = NULL;

    if (db_path == NULL || username == NULL || *username == '\0') {
        return -1;
    }

    if (db_permissions_ok(db_path) != 0) {
        return -1;
    }

    fp = fopen(db_path, "re");
    if (fp == NULL) {
        return -1;
    }

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
