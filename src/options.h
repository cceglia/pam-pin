#ifndef PAM_PIN_OPTIONS_H
#define PAM_PIN_OPTIONS_H

#include <limits.h>

typedef struct module_options {
    int max_tries;
    int fail_delay_ms;
    int debug;
    int pin_min_len;
    int pin_max_len;
    char pin_db[PATH_MAX];
    char state_dir[PATH_MAX];
} module_options;

void options_set_defaults(module_options *opts);
void options_parse(module_options *opts, int argc, const char **argv);

#endif
