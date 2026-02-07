#include "options.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PIN_DB "/etc/security/pam_pin.db"
#define DEFAULT_STATE_DIR "/run/pam-pin"

static int clamp_int(int value, int minv, int maxv)
{
    if (value < minv) {
        return minv;
    }
    if (value > maxv) {
        return maxv;
    }
    return value;
}

static int parse_int(const char *value, int *out)
{
    char *end = NULL;
    long parsed;

    if (value == NULL || *value == '\0') {
        return -1;
    }

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

void options_set_defaults(module_options *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->max_tries = 3;
    opts->fail_delay_ms = 500;
    opts->debug = 0;
    opts->pin_min_len = 4;
    opts->pin_max_len = 10;
    (void)strncpy(opts->pin_db, DEFAULT_PIN_DB, sizeof(opts->pin_db) - 1);
    opts->pin_db[sizeof(opts->pin_db) - 1] = '\0';
    (void)strncpy(opts->state_dir, DEFAULT_STATE_DIR, sizeof(opts->state_dir) - 1);
    opts->state_dir[sizeof(opts->state_dir) - 1] = '\0';
}

void options_parse(module_options *opts, int argc, const char **argv)
{
    int i;

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
            (void)strncpy(opts->pin_db, eq + 1, sizeof(opts->pin_db) - 1);
            opts->pin_db[sizeof(opts->pin_db) - 1] = '\0';
            continue;
        }

        if (strncmp(arg, "state_dir=", 10) == 0) {
            (void)strncpy(opts->state_dir, eq + 1, sizeof(opts->state_dir) - 1);
            opts->state_dir[sizeof(opts->state_dir) - 1] = '\0';
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
        opts->pin_min_len = opts->pin_max_len;
    }
}
