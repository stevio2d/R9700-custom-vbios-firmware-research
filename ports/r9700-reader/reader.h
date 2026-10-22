#ifndef R9700_READER_H
#define R9700_READER_H
#include <stdint.h>
#include <stddef.h>
#define TARGET_BDF "0000:03:00.0"
#define TARGET_PCI "1002:7551/1eae:9801/c0"
#define BUFFER_SIZE 65536U
#define CAPACITY_LIMIT (UINT64_C(256) * 1024 * 1024)
struct geometry {
    uint64_t capacity;
    size_t alignment, max_transfer;
    int positive_id, complete_topology;
};
struct session {
    struct geometry geometry;
    uint64_t generation;
    unsigned calls, resources;
    int opened;
};
struct options {
    const char *fixture;
    uint64_t capacity;
    size_t alignment;
};
extern const int transport_synthetic;
extern const char *transport_name;
void transport_configure(const struct options *options);
const char *transport_open(const char *bdf, struct session *session);
const char *transport_identify(struct session *session, struct geometry *geometry);
const char *transport_check(struct session *session);
const char *transport_read(struct session *session, uint64_t offset, size_t length,
                           unsigned char *buffer, size_t *received);
const char *transport_close(struct session *session);
/* Pure scheduling: aligned transport window and useful subrange; no I/O. */
int read_window(const struct geometry *geometry, uint64_t offset, uint64_t length,
                uint64_t *start, size_t *wire, size_t *skip, size_t *useful);
#endif
