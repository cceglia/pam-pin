#include "retry_store.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define RETRY_COUNT_MAX 1000000

/* Create or validate the retry directory with strict permissions. */
static int open_retry_dir(const char *retry_dir)
{
    struct stat st;
    int dirfd;

    if (retry_dir == NULL || *retry_dir == '\0') {
        return -1;
    }

    if (mkdir(retry_dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    dirfd = open(retry_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) {
        return -1;
    }

    if (fstat(dirfd, &st) != 0) {
        close(dirfd);
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        close(dirfd);
        return -1;
    }

    if (st.st_uid != 0) {
        close(dirfd);
        return -1;
    }

    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(dirfd);
        return -1;
    }

    return dirfd;
}

/* Convert a username into a safe file component, rejecting truncation. */
static int sanitize_username(const char *username, char *out, size_t out_len)
{
    size_t i = 0;

    if (out_len == 0) {
        return -1;
    }

    if (username == NULL || *username == '\0') {
        out[0] = '\0';
        return 0;
    }

    while (*username != '\0' && i + 1 < out_len) {
        unsigned char ch = (unsigned char)*username;
        if (isalnum(ch) || ch == '.' || ch == '_' || ch == '-') {
            out[i++] = (char)ch;
        } else {
            out[i++] = '_';
        }
        ++username;
    }

    if (*username != '\0') {
        out[0] = '\0';
        return -1;
    }

    out[i] = '\0';
    return 0;
}

/* Build the retry counter file name for a user. */
static int build_retry_name(const char *username, char *out, size_t out_len)
{
    char safe_user[256];
    size_t user_len;
    const char *suffix = ".retry";
    size_t suffix_len = strlen(suffix);

    if (username == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    if (sanitize_username(username, safe_user, sizeof(safe_user)) != 0) {
        return -1;
    }
    if (safe_user[0] == '\0') {
        (void)strncpy(safe_user, "user", sizeof(safe_user) - 1);
        safe_user[sizeof(safe_user) - 1] = '\0';
    }

    user_len = strlen(safe_user);
    if (user_len + suffix_len + 1 > out_len) {
        return -1;
    }

    memcpy(out, safe_user, user_len);
    memcpy(out + user_len, suffix, suffix_len);
    out[user_len + suffix_len] = '\0';
    return 0;
}

/* Parse a retry counter value from a string buffer. */
static int parse_retry_count(const char *buf, int *count_out)
{
    char *end = NULL;
    long parsed;

    if (buf == NULL || *buf == '\0') {
        *count_out = 0;
        return 0;
    }

    errno = 0;
    parsed = strtol(buf, &end, 10);
    if (errno != 0 || end == buf) {
        return -1;
    }

    if (*end != '\0' && *end != '\n') {
        return -1;
    }

    if (parsed < 0 || parsed > RETRY_COUNT_MAX) {
        return -1;
    }

    *count_out = (int)parsed;
    return 0;
}

/* Read the retry count from a locked file descriptor. */
static int read_count_locked(int fd, int *count_out)
{
    char buf[32];
    ssize_t nread;

    if (count_out == NULL) {
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        return -1;
    }

    nread = read(fd, buf, sizeof(buf) - 1);
    if (nread < 0) {
        return -1;
    }

    buf[nread] = '\0';
    return parse_retry_count(buf, count_out);
}

/* Write the retry count to a locked file descriptor. */
static int write_count_locked(int fd, int count)
{
    char buf[32];
    int len;
    ssize_t nwritten;

    len = snprintf(buf, sizeof(buf), "%d\n", count);
    if (len <= 0 || (size_t)len >= sizeof(buf)) {
        return -1;
    }

    if (ftruncate(fd, 0) != 0) {
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        return -1;
    }

    nwritten = write(fd, buf, (size_t)len);
    if (nwritten != (ssize_t)len) {
        return -1;
    }

    return 0;
}

/* Validate that a retry file has secure ownership and mode. */
static int file_permissions_ok(int fd)
{
    struct stat st;

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

/* Read the persisted retry count for a user. */
int retry_store_read(const char *retry_dir, const char *username, int *count_out)
{
    char name[300];
    int dirfd;
    int fd;
    int count = 0;
    int result = 0;

    if (count_out == NULL) {
        return -1;
    }

    *count_out = 0;

    dirfd = open_retry_dir(retry_dir);
    if (dirfd < 0) {
        return -1;
    }

    if (build_retry_name(username, name, sizeof(name)) != 0) {
        close(dirfd);
        return -1;
    }

    fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            close(dirfd);
            return 0;
        }
        close(dirfd);
        return -1;
    }

    if (flock(fd, LOCK_SH) != 0) {
        close(fd);
        close(dirfd);
        return -1;
    }

    if (file_permissions_ok(fd) != 0) {
        result = -1;
    } else if (read_count_locked(fd, &count) != 0) {
        result = -1;
    } else {
        *count_out = count;
    }

    (void)flock(fd, LOCK_UN);
    close(fd);
    close(dirfd);
    return result;
}

/* Increment and persist the retry count for a user. */
int retry_store_increment(const char *retry_dir, const char *username, int *count_out)
{
    char name[300];
    int dirfd;
    int fd;
    int count = 0;
    int result = 0;

    if (count_out == NULL) {
        return -1;
    }

    *count_out = 0;

    dirfd = open_retry_dir(retry_dir);
    if (dirfd < 0) {
        return -1;
    }

    if (build_retry_name(username, name, sizeof(name)) != 0) {
        close(dirfd);
        return -1;
    }

    fd = openat(dirfd, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        close(dirfd);
        return -1;
    }

    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        close(dirfd);
        return -1;
    }

    if (file_permissions_ok(fd) != 0) {
        result = -1;
    } else if (read_count_locked(fd, &count) != 0) {
        result = -1;
    } else {
        if (count < RETRY_COUNT_MAX) {
            count += 1;
        }
        if (write_count_locked(fd, count) != 0) {
            result = -1;
        } else {
            *count_out = count;
        }
    }

    (void)flock(fd, LOCK_UN);
    close(fd);
    close(dirfd);
    return result;
}

/* Remove the persisted retry count for a user. */
int retry_store_clear(const char *retry_dir, const char *username)
{
    char name[300];
    int dirfd;

    dirfd = open_retry_dir(retry_dir);
    if (dirfd < 0) {
        return -1;
    }

    if (build_retry_name(username, name, sizeof(name)) != 0) {
        close(dirfd);
        return -1;
    }

    if (unlinkat(dirfd, name, 0) != 0) {
        if (errno == ENOENT) {
            close(dirfd);
            return 0;
        }
        close(dirfd);
        return -1;
    }

    close(dirfd);
    return 0;
}
