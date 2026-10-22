#define _GNU_SOURCE
#include "reader.h"
#include "record.h"
#include "build.h"
#include "image.h"
#include "cached_inventory.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t cancelled;
static void on_signal(int sig) { (void)sig; cancelled = 1; }
static void utc(char out[128])
{
    time_t now = time(NULL); struct tm t;
    if (!gmtime_r(&now, &t) || !strftime(out,128,"%Y-%m-%dT%H:%M:%SZ",&t)) strcpy(out,"unavailable");
}
static int random_id(char out[128])
{
    unsigned char b[16]; size_t off = 0;
    while (off < sizeof(b)) {
        ssize_t n = getrandom(b + off, sizeof(b) - off, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    for (size_t i = 0; i < sizeof(b); i++) (void)snprintf(out+2*i,3,"%02x",b[i]);
    return 0;
}
static int fault(const struct options *o, const char *name)
{
#ifdef TEST_TRANSPORT
    return !strcmp(o->fixture,name);
#else
    (void)o; (void)name; return 0;
#endif
}
static int sync_parent(const char *path)
{
    char *copy = strdup(path);
    if (!copy) return -1;
    char *slash = strrchr(copy, '/');
    if (slash) { if (slash == copy) slash[1] = 0; else *slash = 0; }
    int fd = open(slash ? copy : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(copy);
    if (fd < 0) return -1;
    int error = fsync(fd);
    if (close(fd)) error = -1;
    return error;
}
static int backup(const char *bdf, const char *path, const struct options *options)
{
    struct record r = {0}; struct session s = {0}; struct geometry g = {0};
    int dir = -1, data = -1, ledger = -1, recorded = 0;
    const char *error = NULL;
    uint64_t offset = 0, chunks = 0, size = 0, start;
    size_t wire, skip, useful; char hash[65], line[128];
    unsigned char buffer[BUFFER_SIZE];
    set(&r,F_SCHEMA,"r9700-reader-v1"); set(&r,F_CLASS,"synthetic");
    set(&r,F_STATUS,"incomplete"); set(&r,F_ERROR,"unfinished");
    set(&r,F_BDF,bdf); set(&r,F_PCI,TARGET_PCI); set(&r,F_HOST,"synthetic-four-device-host");
    set(&r,F_KERNEL,"synthetic-none"); set(&r,F_FIRMWARE,"synthetic-none");
    set(&r,F_BACKEND,transport_name); set(&r,F_BUILD,BUILD_SHA256);
    set(&r,F_CLEANUP,"not-started"); set(&r,F_END,"pending");
    set(&r,F_CHIP,"unidentified"); set(&r,F_TOPOLOGY,"unknown"); set(&r,F_COVERAGE,"unproven");
    set(&r,F_SHA,"pending"); set(&r,F_LEDGER_SHA,"pending");
    for (enum field f = F_CAPACITY; f <= F_MAX_TRANSFER; f++) number(&r,f,0);
    number(&r,F_GENERATION,0); number(&r,F_BYTES,0); number(&r,F_CHUNKS,0); number(&r,F_RESOURCES,0);
    utc(r.value[F_START]);
    if (random_id(r.value[F_ID])) return 1;
    int self = open("/proc/self/exe",O_RDONLY | O_CLOEXEC);
    if (self < 0) return 1;
    int hash_error = digest_fd(self,hash,&size);
    if (close(self)) hash_error = -1;
    if (hash_error) return 1;
    set(&r,F_EXE,hash);
    if (mkdir(path,0700)) { perror("exclusive output directory"); return 1; }
    dir = open(path,O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || sync_parent(path)) { error = "output-directory-sync"; goto done; }
    int marker = openat(dir,"incomplete",O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,0600);
    if (marker < 0) { error = "incomplete-marker"; goto done; }
    int marker_error = write_all(marker,"incomplete\n",11) || fsync(marker);
    if (close(marker)) marker_error = 1;
    if (marker_error || fsync(dir)) { error = "incomplete-marker-sync"; goto done; }
    if (record_write(dir,&r,0)) { error = "initial-record"; goto done; }
    recorded = 1;
    data = openat(dir,"data.bin",O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,0600);
    ledger = openat(dir,"coverage.tsv",O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,0600);
    if (data < 0 || ledger < 0 || fsync(dir)) { error = "output-create"; goto done; }
    if (cancelled) { error = "cancelled"; goto done; }
    error = transport_open(bdf,&s);
    if (s.opened) set(&r,F_CLEANUP,"pending");
    if (error) goto done;
    error = transport_identify(&s,&g);
    if (error) goto done;
    if (read_window(&g,0,g.capacity,&start,&wire,&skip,&useful)) { error = "unqualified-geometry"; goto done; }
    number(&r,F_CAPACITY,g.capacity); number(&r,F_ALIGNMENT,g.alignment); number(&r,F_MAX_TRANSFER,g.max_transfer);
    number(&r,F_GENERATION,s.generation); set(&r,F_CHIP,"synthetic-address-pattern");
    set(&r,F_TOPOLOGY,"synthetic-one-bank"); set(&r,F_COVERAGE,"synthetic-linear");
    while (offset < g.capacity) {
        if (cancelled) { error = "cancelled"; break; }
        error = transport_check(&s);
        if (error) break;
        if (read_window(&g,offset,g.capacity-offset,&start,&wire,&skip,&useful)) { error = "range"; break; }
        size_t received = 0;
        error = transport_read(&s,start,wire,buffer,&received);
        if (error) break;
        if (received != wire) { error = "malformed-response-length"; break; }
        /* Detect reset/identity changes before retaining this response. */
        error = transport_check(&s);
        if (error) break;
        if (cancelled) { error = "cancelled"; break; }
        if (chunks == 1 && fault(options,"storage")) {
            if (write_all(data,buffer+skip,4096)) error = "storage";
            error = "storage"; break;
        }
        if (write_all(data,buffer+skip,useful)) { error = "data-write"; break; }
        int n = snprintf(line,sizeof(line),"%" PRIu64 " %zu\n",offset,useful);
        if (n < 0 || (size_t)n >= sizeof(line) || write_all(ledger,line,(size_t)n)) { error = "coverage-write"; break; }
        if (fsync(data) || fsync(ledger)) { error = "chunk-sync"; break; }
        offset += useful; chunks++;
    }
    if (!error) error = transport_check(&s);
done:
    if (s.opened) {
        const char *cleanup_error = transport_close(&s);
        set(&r,F_CLEANUP,cleanup_error ? "failed" : "ok");
        if (cleanup_error && !error) error = cleanup_error;
    }
    number(&r,F_RESOURCES,s.resources); number(&r,F_CHUNKS,chunks);
    if (s.resources && !error) error = "resource-leak";
    if (cancelled && !error) error = "cancelled";
    if (data >= 0) {
        if (fsync(data) || fault(options,"sync")) error = "data-sync";
        if (digest_fd(data,hash,&size)) { error = "data-hash"; set(&r,F_SHA,"unavailable"); }
        else { set(&r,F_SHA,hash); number(&r,F_BYTES,size); }
        if (close(data) || fault(options,"close")) error = "data-close";
    }
    if (ledger >= 0) {
        if (fsync(ledger)) error = "coverage-sync";
        if (digest_fd(ledger,hash,&size)) { error = "coverage-hash"; set(&r,F_LEDGER_SHA,"unavailable"); }
        else set(&r,F_LEDGER_SHA,hash);
        if (close(ledger)) error = "coverage-close";
    }
    if (!error && offset != g.capacity) error = "incomplete-coverage";
    utc(r.value[F_END]); set(&r,F_STATUS,error ? "failed" : "complete");
    set(&r,F_ERROR,error ? error : "none");
    if (dir >= 0) {
        if (!recorded || fault(options,"record") || record_write(dir,&r,fault(options,"record-sync"))) error = "final-record";
        /* All data, record and directory writes are durable before removing the
         * rejection marker. A crash can resurrect the marker (safe rejection).
         * No further fallible persistence step follows publication. */
        if (!error && unlinkat(dir,"incomplete",0)) error = "completion-marker";
        (void)close(dir); /* read-only directory; no pending data writes */
    }
    if (error) { fprintf(stderr,"acquisition failed: %s; retain %s\n",error,path); return 1; }
    puts("{\"status\":\"complete\",\"classification\":\"synthetic\",\"physical_backup_verified\":false}"); return 0;
}
static int identify(const char *bdf)
{
    struct session s = {0}; struct geometry g = {0};
    const char *error = transport_open(bdf,&s);
    if (!error) error = transport_identify(&s,&g);
    uint64_t start; size_t wire,skip,useful;
    if (!error && read_window(&g,0,g.capacity,&start,&wire,&skip,&useful)) error = "unqualified-geometry";
    if (!error) error = transport_check(&s);
    if (s.opened) { const char *e = transport_close(&s); if (e && !error) error = e; }
    if (error) { fprintf(stderr,"identification failed: %s\n",error); return 1; }
    printf("{\"classification\":\"synthetic\",\"bdf\":\"%s\",\"capacity\":%" PRIu64 ",\"cleanup\":\"ok\",\"resources\":%u}\n",bdf,g.capacity,s.resources);
    return 0;
}
static int usage(void)
{
    fputs("usage: r9700-reader COMMAND [OPTIONS]\n"
          "  list | info --bdf FULL_BDF                         cached inventory\n"
          "  inspect --file FILE                              offline BIOS/IFWI\n"
          "  checksum --file FILE [--scope SCOPE] [--expect N]  offline byte sum\n"
          "  compare --kind part-number|partition --left FILE --right FILE\n"
          "  plan | identify --bdf FULL_BDF                    live identify disabled\n"
          "  backup --bdf FULL_BDF --output NEW_DIR             live backup disabled\n"
          "  verify --synthetic DIR1 DIR2 DIR3                  synthetic v1 only\n",stderr);
    return 2;
}
int main(int argc, char **argv)
{
    if (argc < 2) return usage();
    if (!strcmp(argv[1],"list")) {
        if (argc != 2) return usage();
        puts(CACHED_LIST); return 0;
    }
    if (!strcmp(argv[1],"info")) {
        if (argc != 4 || strcmp(argv[2],"--bdf")) return usage();
        for (size_t i = 0; i < sizeof(cached_bdfs)/sizeof(cached_bdfs[0]); i++) {
            if (!strcmp(argv[3],cached_bdfs[i])) { puts(cached_info[i]); return 0; }
        }
        fputs("BDF absent from cached inventory\n",stderr); return 1;
    }
    if (!strcmp(argv[1],"inspect") || !strcmp(argv[1],"checksum") || !strcmp(argv[1],"compare")) return image_commands(argc,argv);
    if (!strcmp(argv[1],"verify")) {
        if (argc != 6 || strcmp(argv[2],"--synthetic")) return usage();
        return verify_acquisitions(3,argv+3,1);
    }
    if (!strcmp(argv[1],"plan")) {
        if (argc != 2) return usage();
        printf("{\"live_enabled\":false,\"backend\":\"%s\",\"synthetic_build\":%s,\"build_sha256\":\"%s\",\"blockers\":[\"protocol\",\"exact-kernel-integration\",\"physical-geometry-and-topology\",\"separate-hardware-approval\"]}\n",transport_name,transport_synthetic ? "true" : "false",BUILD_SHA256);
        return 0;
    }
    int is_backup = !strcmp(argv[1],"backup");
    if (!is_backup && strcmp(argv[1],"identify")) return usage();
    const char *bdf = NULL, *output = NULL;
    struct options options = {"normal",UINT64_C(2097164),4};
    int fixture_seen = 0, cap_seen = 0, align_seen = 0;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) return usage();
        if (!strcmp(argv[i],"--bdf") && !bdf) bdf = argv[i+1];
        else if (!strcmp(argv[i],"--output") && !output && is_backup) output = argv[i+1];
#ifdef TEST_TRANSPORT
        else if (!strcmp(argv[i],"--fixture") && !fixture_seen++) options.fixture = argv[i+1];
        else if (!strcmp(argv[i],"--capacity") && !cap_seen++) {
            if (parse_u64(argv[i+1],&options.capacity)) return usage();
        }
        else if (!strcmp(argv[i],"--alignment") && !align_seen++) {
            uint64_t n;
            if (parse_u64(argv[i+1],&n) || n > SIZE_MAX) return usage();
            options.alignment = (size_t)n;
        }
#endif
        else return usage();
    }
    (void)fixture_seen; (void)cap_seen; (void)align_seen;
    if (!bdf || strcmp(bdf,TARGET_BDF) || (is_backup && !output)) return usage();
    /* The live build stops before filesystem output or transport activity. */
    if (!transport_synthetic) { fputs("live-disabled: protocol, kernel integration and hardware approval are incomplete\n",stderr); return 2; }
    const char *const fixtures[] = {"normal","init","identify","unknown","topology","conflict","identity","reset","read","timeout","cancel","crash","short","oversized","cleanup","storage","sync","close","record","record-sync"};
    int valid = 0;
    for (size_t i = 0; i < sizeof(fixtures)/sizeof(fixtures[0]); i++) if (!strcmp(options.fixture,fixtures[i])) valid = 1;
    if (!valid) return usage();
    transport_configure(&options);
    struct sigaction action = {0}; action.sa_handler = on_signal; sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM,&action,NULL) || sigaction(SIGINT,&action,NULL) || sigaction(SIGALRM,&action,NULL)) return 1;
    alarm(30); /* Mock execution bound only; no claim of kernel-owned cleanup. */
    return is_backup ? backup(bdf,output,&options) : identify(bdf);
}
