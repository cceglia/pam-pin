#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "crypto.h"
#include "options.h"
#include "pin_store.h"

static void maybe_log_debug(pam_handle_t *pamh, const module_options *opts, const char *msg)
{
    /* Emit debug logs only when the module is explicitly configured with debug. */
    if (opts->debug) {
        pam_syslog(pamh, LOG_DEBUG, "%s", msg);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    module_options opts;
    const char *user = NULL;
    const char *token = NULL;
    int pam_rc;
    int lookup_rc;
    char *stored_hash = NULL;
    int attempt;

    (void)flags;

    /* Load module defaults first, then override them with PAM arguments. */
    options_set_defaults(&opts);
    options_parse(&opts, argc, argv);

    pam_rc = pam_get_user(pamh, &user, NULL);
    if (pam_rc != PAM_SUCCESS || user == NULL || *user == '\0') {
        maybe_log_debug(pamh, &opts, "pam_pin: no valid user, fallback to next module");
        return PAM_IGNORE;
    }

    lookup_rc = pin_store_lookup_hash(opts.pin_db, user, &stored_hash);
    if (lookup_rc <= 0) {
        maybe_log_debug(pamh, &opts, "pam_pin: no PIN entry or db issue, fallback to next module");
        return PAM_IGNORE;
    }

    /*
     * Prompt once per attempt using a shared "PIN or Password" field.
     * If the token is not a numeric PIN, immediately fall through so the next
     * module (typically pam_unix with try_first_pass) can treat it as password.
     */
    for (attempt = 1; attempt <= opts.max_tries; ++attempt) {
        int verified;

        pam_rc = pam_get_authtok(pamh, PAM_AUTHTOK, &token, "PIN or Password");
        if (pam_rc != PAM_SUCCESS || token == NULL) {
            maybe_log_debug(pamh, &opts, "pam_pin: prompt failed, fallback to next module");
            free(stored_hash);
            return PAM_IGNORE;
        }

        if (!crypto_pin_format_valid(token, opts.pin_min_len, opts.pin_max_len)) {
            maybe_log_debug(pamh, &opts, "pam_pin: non-PIN token, fallback to password module");
            free(stored_hash);
            return PAM_IGNORE;
        }

        verified = crypto_verify_pin_hash(token, stored_hash);

        if (verified) {
            maybe_log_debug(pamh, &opts, "pam_pin: PIN accepted");
            free(stored_hash);
            return PAM_SUCCESS;
        }

        /* Clear cached authtok so a wrong PIN is not reused by downstream modules. */
        if (pam_set_item(pamh, PAM_AUTHTOK, NULL) != PAM_SUCCESS) {
            free(stored_hash);
            return PAM_IGNORE;
        }

        /* Apply a linear backoff delay to slow down online brute-force attempts. */
        if (opts.fail_delay_ms > 0) {
            uint64_t delay_us64 = (uint64_t)opts.fail_delay_ms * (uint64_t)attempt * 1000ULL;
            unsigned int delay_us = (delay_us64 > (uint64_t)UINT_MAX) ? UINT_MAX : (unsigned int)delay_us64;
            pam_fail_delay(pamh, delay_us);
        }
    }

    maybe_log_debug(pamh, &opts, "pam_pin: PIN attempts exceeded, fallback to password");
    free(stored_hash);
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;
    (void)pamh;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
