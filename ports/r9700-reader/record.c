#define _GNU_SOURCE
#include "record.h"
#include "reader.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#define NAME(a,b) #b,
static const char *const names[] = { FIELDS(NAME) };
#undef NAME
void set(struct record *r, enum field f, const char *v)
{ (void)snprintf(r->value[f], sizeof(r->value[f]), "%s", v); }
void number(struct record *r, enum field f, uint64_t v)
{ (void)snprintf(r->value[f], sizeof(r->value[f]), "%" PRIu64, v); }
int parse_u64(const char *s, uint64_t *v)
{
    if (!*s) return -1;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return -1;
    errno = 0; char *end;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || *end || n > UINT64_MAX) return -1;
    *v = (uint64_t)n; return 0;
}
int write_all(int fd, const void *data, size_t size)
{
    const unsigned char *p = data;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += (size_t)n; size -= (size_t)n;
    }
    return 0;
}
int open_regular(int dir, const char *name)
{
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) || !S_ISREG(st.st_mode))) { close(fd); return -1; }
    return fd;
}
int record_write(int dir, const struct record *r, int fail_after_rename)
{
    int fd = openat(dir, "record.next", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int error = 0;
    for (int i = 0; i < F_COUNT; i++) {
        char line[256];
        int n = snprintf(line, sizeof(line), "%s=%s\n", names[i], r->value[i]);
        if (n < 0 || (size_t)n >= sizeof(line) || write_all(fd, line, (size_t)n)) error = 1;
    }
    if (fsync(fd)) error = 1;
    if (close(fd)) error = 1;
    if (error || renameat(dir, "record.next", dir, "acquisition.record") || fail_after_rename || fsync(dir)) return -1;
    return 0;
}
int record_read(int dir, struct record *r)
{
    int fd = open_regular(dir, "acquisition.record");
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return -1; }
    char line[256]; int error = 0;
    for (int i = 0; i < F_COUNT; i++) {
        if (!fgets(line, sizeof(line), f)) { error = 1; break; }
        size_t n = strlen(line), k = strlen(names[i]);
        if (!n || line[n-1] != '\n' || strncmp(line, names[i], k) || line[k] != '=' ||
            n < k + 3 || n - k - 2 >= sizeof(r->value[i])) { error = 1; break; }
        line[n-1] = 0;
        /* Embedded NULs, duplicate/unknown keys and extra lines are rejected. */
        set(r, (enum field)i, line + k + 1);
    }
    if (fgetc(f) != EOF || ferror(f)) error = 1;
    if (fclose(f)) error = 1;
    return error ? -1 : 0;
}
int digest_fd(int fd, char hex[65], uint64_t *size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); unsigned char buf[BUFFER_SIZE], hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0; int error = 0; *size = 0;
    if (!ctx) return -1;
    if (lseek(fd, 0, SEEK_SET) < 0 || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) error = 1;
    while (!error) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { error = 1; break; }
        if (!n) break;
        if ((uint64_t)n > CAPACITY_LIMIT - *size || EVP_DigestUpdate(ctx, buf, (size_t)n) != 1)
            { error = 1; break; }
        *size += (uint64_t)n;
    }
    if (!error && (EVP_DigestFinal_ex(ctx, hash, &length) != 1 || length != 32)) error = 1;
    EVP_MD_CTX_free(ctx);
    if (error) return -1;
    for (unsigned int i = 0; i < length; i++) (void)snprintf(hex + 2*i, 3, "%02x", hash[i]);
    return 0;
}
static int is_hex(const char *s, size_t n)
{
    if (strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++) if (!strchr("0123456789abcdef", s[i])) return 0;
    return 1;
}
static int timestamp(const char *s)
{
    if (strlen(s) != 20) return 0;
    for (size_t i = 0; i < 20; i++) {
        char separator = i == 4 || i == 7 ? '-' : i == 10 ? 'T' : i == 13 || i == 16 ? ':' : i == 19 ? 'Z' : 0;
        if (separator ? s[i] != separator : (s[i] < '0' || s[i] > '9')) return 0;
    }
    return 1;
}
static int coverage(int fd, uint64_t capacity, uint64_t chunks, uint64_t alignment, uint64_t max)
{
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    FILE *f = fdopen(dup(fd), "r");
    if (!f) return -1;
    char line[128], canonical[128]; uint64_t off = 0, count = 0; int error = 0;
    while (fgets(line, sizeof(line), f)) {
        uint64_t a, n;
        char *separator = strchr(line, ' '), *newline = strchr(line, '\n');
        if (!separator || !newline || newline[1] || separator >= newline) { error = 1; break; }
        *separator = 0; *newline = 0;
        if (parse_u64(line, &a) || parse_u64(separator + 1, &n) ||
            a != off || a > capacity || !n || n > capacity - a || n > max ||
            a % alignment || n % alignment) { error = 1; break; }
        (void)snprintf(canonical, sizeof(canonical), "%" PRIu64 " %" PRIu64 "\n", a, n);
        *separator = ' '; *newline = '\n';
        if (strcmp(line, canonical)) { error = 1; break; }
        off += n; count++;
    }
    if (ferror(f) || off != capacity || count != chunks) error = 1;
    if (fclose(f)) error = 1;
    return error ? -1 : 0;
}
static int verify_one(const char *path, struct record *r)
{
    int dir = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int data = -1, ledger = -1, error = 1;
    uint64_t cap, bytes, chunks, align, max, size;
    char hash[65];
    if (dir < 0 || record_read(dir, r)) goto done;
    struct stat marker;
    if (fstatat(dir, "incomplete", &marker, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) goto done;
#define EQ(field, text) (strcmp(r->value[F_##field], text) == 0)
    if (!EQ(SCHEMA,"r9700-reader-v1") || !EQ(CLASS,"synthetic") || !EQ(STATUS,"complete") ||
        !EQ(ERROR,"none") || !EQ(BDF,TARGET_BDF) || !EQ(PCI,TARGET_PCI) ||
        !EQ(HOST,"synthetic-four-device-host") || !EQ(KERNEL,"synthetic-none") ||
        !EQ(FIRMWARE,"synthetic-none") || !EQ(BACKEND,"synthetic-mock-v1") ||
        !EQ(CHIP,"synthetic-address-pattern") || !EQ(TOPOLOGY,"synthetic-one-bank") ||
        !EQ(COVERAGE,"synthetic-linear") || !EQ(GENERATION,"1") ||
        !EQ(CLEANUP,"ok") || !EQ(RESOURCES,"0") ||
        !is_hex(r->value[F_BUILD],64) || !is_hex(r->value[F_EXE],64) ||
        !is_hex(r->value[F_ID],32) || !timestamp(r->value[F_START]) ||
        !timestamp(r->value[F_END]) || strcmp(r->value[F_START], r->value[F_END]) > 0 ||
        parse_u64(r->value[F_CAPACITY], &cap) || !cap || cap > CAPACITY_LIMIT ||
        parse_u64(r->value[F_BYTES], &bytes) || bytes != cap ||
        parse_u64(r->value[F_CHUNKS], &chunks) || !chunks ||
        parse_u64(r->value[F_ALIGNMENT], &align) || !align || align > BUFFER_SIZE || cap % align ||
        parse_u64(r->value[F_MAX_TRANSFER], &max) || !max || max > BUFFER_SIZE || max % align ||
        !is_hex(r->value[F_SHA],64) || !is_hex(r->value[F_LEDGER_SHA],64)) goto done;
    data = open_regular(dir,"data.bin"); ledger = open_regular(dir,"coverage.tsv");
    if (data < 0 || ledger < 0 || digest_fd(data, hash, &size) || size != cap ||
        strcmp(hash, r->value[F_SHA]) || digest_fd(ledger, hash, &size) ||
        strcmp(hash, r->value[F_LEDGER_SHA]) || coverage(ledger, cap, chunks, align, max)) goto done;
    error = 0;
done:
    if (data >= 0 && close(data)) error = 1;
    if (ledger >= 0 && close(ledger)) error = 1;
    if (dir >= 0 && close(dir)) error = 1;
    return error ? -1 : 0;
#undef EQ
}
static int equal_data(const char *a, const char *b)
{
    int da = open(a, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int db = open(b, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int fa = da < 0 ? -1 : open_regular(da,"data.bin");
    int fb = db < 0 ? -1 : open_regular(db,"data.bin");
    int error = 0; unsigned char ba[BUFFER_SIZE], bb[BUFFER_SIZE];
    if (fa < 0 || fb < 0) error = 1;
    while (!error) {
        ssize_t na = read(fa, ba, sizeof(ba)), nb = read(fb, bb, sizeof(bb));
        if (na < 0 || nb < 0 || na != nb || memcmp(ba, bb, (size_t)na)) { error = 1; break; }
        if (!na) break;
    }
    if (fa >= 0 && close(fa)) error = 1;
    if (fb >= 0 && close(fb)) error = 1;
    if (da >= 0 && close(da)) error = 1;
    if (db >= 0 && close(db)) error = 1;
    return error ? -1 : 0;
}
int verify_acquisitions(int count, char **paths, int synthetic)
{
    struct record records[3];
    if (!synthetic || count != 3) {
        fputs("verification requires --synthetic and exactly three sessions; physical verification is unavailable\n", stderr);
        return 2;
    }
    for (int i = 0; i < count; i++) {
        if (verify_one(paths[i], &records[i])) { fprintf(stderr,"invalid acquisition: %s\n",paths[i]); return 1; }
        for (int j = 0; j < i; j++) if (!strcmp(records[i].value[F_ID], records[j].value[F_ID])) {
            fputs("sessions must have distinct acquisition IDs\n",stderr); return 1;
        }
        if (i) {
            const enum field same[] = {F_BDF,F_PCI,F_BACKEND,F_BUILD,F_EXE,F_CAPACITY,F_ALIGNMENT,
                F_MAX_TRANSFER,F_CHIP,F_TOPOLOGY,F_COVERAGE,F_SHA};
            for (size_t k = 0; k < sizeof(same)/sizeof(same[0]); k++)
                if (strcmp(records[0].value[same[k]], records[i].value[same[k]])) return 1;
            if (equal_data(paths[0],paths[i])) return 1;
        }
    }
    puts("{\"verified\":true,\"classification\":\"synthetic\",\"sessions\":3,\"physical_backup_verified\":false}");
    return 0;
}
