#ifndef R9700_RECORD_H
#define R9700_RECORD_H
#include <stdint.h>
#include <stddef.h>
#define FIELDS(X) \
 X(SCHEMA,schema) X(CLASS,classification) X(STATUS,status) X(ERROR,error) \
 X(BDF,bdf) X(PCI,pci) X(HOST,host) X(KERNEL,kernel) X(FIRMWARE,firmware) \
 X(BACKEND,backend) X(BUILD,build_sha256) X(EXE,executable_sha256) \
 X(ID,acquisition_id) X(START,start_utc) X(END,end_utc) \
 X(CAPACITY,capacity) X(ALIGNMENT,alignment) X(MAX_TRANSFER,max_transfer) \
 X(CHIP,chip_id) X(TOPOLOGY,topology) X(COVERAGE,coverage_kind) \
 X(GENERATION,generation) X(BYTES,bytes) X(SHA,sha256) \
 X(LEDGER_SHA,coverage_sha256) X(CLEANUP,cleanup) X(RESOURCES,resources) X(CHUNKS,chunks)
#define ENUM(a,b) F_##a,
enum field { FIELDS(ENUM) F_COUNT };
#undef ENUM
struct record { char value[F_COUNT][128]; };
void set(struct record *r, enum field f, const char *v);
void number(struct record *r, enum field f, uint64_t v);
int parse_u64(const char *s, uint64_t *v);
int write_all(int fd, const void *data, size_t size);
int record_write(int dir, const struct record *r, int fail_after_rename);
int record_read(int dir, struct record *r);
int digest_fd(int fd, char hex[65], uint64_t *size);
int open_regular(int dir, const char *name);
int verify_acquisitions(int count, char **paths, int synthetic);
#endif
