#include "options.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PIN_DB "/etc/security/pam_pin.db"
#define DEFAULT_RETRY_DIR "/run/pam_pin"

/* Require absolute paths without ".." segments. */
static int path_is_absolute_clean(const char *path)
{
    const char *p;

    if (path == NULL || path[0] != '/') {
        return 0;
    }

    p = path;
    while ((p = strstr(p, "..")) != NULL) {
        if ((p == path || p[-1] == '/') && (p[2] == '/' || p[2] == '\0')) {
            return 0;
        }
        p += 2;
    }

    return 1;
}

/* Clamp an integer to a fixed range. */
static int clamp_int(int value, int minv, int maxv)
{
    /* Keep option values inside a safe, expected range. */
    if (value < minv) {
        return minv;
    }
    if (value > maxv) {
        return maxv;
    }
    return value;
}

/* Parse a base-10 integer string with strict validation. */
static int parse_int(const char *value, int *out)
{
    char *end = NULL;
    long parsed;

    if (value == NULL || *value == '\0') {
        return -1;
    }

    /* Strict base-10 parse: reject empty strings and trailing garbage. */
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }

    if (parsed < -2147483647L - 1L || parsed > 2147483647L) {
        return -1;
    }

    *out = (int)parsed;
    return 0;
}

/* Initialize module options with conservative defaults. */
void options_set_defaults(module_options *opts)
{
    /* Conservative defaults: PIN-first auth with bounded retries and delay. */
    memset(opts, 0, sizeof(*opts));
    opts->max_tries = 3;
    opts->fail_delay_ms = 500;
    opts->debug = 0;
    opts->pin_min_len = 4;
    opts->pin_max_len = 10;
    (void)strncpy(opts->pin_db, DEFAULT_PIN_DB, sizeof(opts->pin_db) - 1);
    opts->pin_db[sizeof(opts->pin_db) - 1] = '\0';
    (void)strncpy(opts->retry_dir, DEFAULT_RETRY_DIR, sizeof(opts->retry_dir) - 1);
    opts->retry_dir[sizeof(opts->retry_dir) - 1] = '\0';
}

/* Override defaults with PAM module arguments. */
void options_parse(module_options *opts, int argc, const char **argv)
{
    int i;

    /* Parse PAM module arguments in key=value form plus the debug flag. */
    for (i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        const char *eq;
        int value;

        if (arg == NULL) {
            continue;
        }

        if (strcmp(arg, "debug") == 0) {
            opts->debug = 1;
            continue;
        }

        eq = strchr(arg, '=');
        if (eq == NULL) {
            continue;
        }

        if (strncmp(arg, "max_tries=", 10) == 0) {
            if (parse_int(eq + 1, &value) == 0) {
                /* Prevent unrealistic values that weaken UX or security posture. */
                opts->max_tries = clamp_int(value, 1, 10);
            }
            continue;
        }

        if (strncmp(arg, "fail_delay_ms=", 14) == 0) {
            if (parse_int(eq + 1, &value) == 0) {
                opts->fail_delay_ms = clamp_int(value, 0, 10000);
            }
            continue;
        }

        if (strncmp(arg, "pin_db=", 7) == 0) {
            if (path_is_absolute_clean(eq + 1)) {
                (void)strncpy(opts->pin_db, eq + 1, sizeof(opts->pin_db) - 1);
                opts->pin_db[sizeof(opts->pin_db) - 1] = '\0';
            }
            continue;
        }

        if (strncmp(arg, "retry_dir=", 10) == 0) {
            if (path_is_absolute_clean(eq + 1)) {
                (void)strncpy(opts->retry_dir, eq + 1, sizeof(opts->retry_dir) - 1);
                opts->retry_dir[sizeof(opts->retry_dir) - 1] = '\0';
            }
            continue;
        }

        if (strncmp(arg, "pin_min_len=", 12) == 0) {
            if (parse_int(eq + 1, &value) == 0) {
                opts->pin_min_len = clamp_int(value, 1, 32);
            }
            continue;
        }

        if (strncmp(arg, "pin_max_len=", 12) == 0) {
            if (parse_int(eq + 1, &value) == 0) {
                opts->pin_max_len = clamp_int(value, 1, 64);
            }
            continue;
        }
    }

    if (opts->pin_min_len > opts->pin_max_len) {
        /* Keep constraints coherent if user passes conflicting limits. */
        opts->pin_min_len = opts->pin_max_len;
    }
}
