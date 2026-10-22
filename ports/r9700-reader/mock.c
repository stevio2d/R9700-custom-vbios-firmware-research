/* Test-only transport. Contains no hardware access and emits no SPI/MMIO commands. */
#include "reader.h"
#include <string.h>
#include <signal.h>
const int transport_synthetic = 1;
const char *transport_name = "synthetic-mock-v1";
static struct options config;
void transport_configure(const struct options *o) { config = *o; }
static int fault(const char *s) { return strcmp(config.fixture, s) == 0; }
const char *transport_open(const char *bdf, struct session *s)
{
    /* Fixture order deliberately places the selected adapter third. */
    static const char *const devices[] = {"0000:0c:00.0", "0000:09:00.0", TARGET_BDF, "0000:06:00.0"};
    unsigned matches = 0;
    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++)
        if (strcmp(bdf, devices[i]) == 0) matches++;
    if (matches != 1) return "selection";
    s->opened = 1; s->resources = 2; s->generation = 1;
    if (fault("init")) return "initialization";
    return NULL;
}
const char *transport_identify(struct session *s, struct geometry *g)
{
    (void)s;
    *g = (struct geometry){config.capacity, config.alignment, BUFFER_SIZE, 1, 1};
    if (fault("unknown")) g->positive_id = 0;
    if (fault("topology")) g->complete_topology = 0;
    if (fault("conflict")) return "conflicting-geometry";
    if (fault("identify")) return "identification";
    return NULL;
}
const char *transport_check(struct session *s)
{
    if (s->calls && fault("identity")) return "identity-changed";
    if (s->calls && fault("reset")) { s->generation = 2; return "device-generation-changed"; }
    return NULL;
}
const char *transport_read(struct session *s, uint64_t off, size_t n,
                           unsigned char *b, size_t *received)
{
    s->calls++;
    if (off > config.capacity || n > config.capacity - off || n > BUFFER_SIZE ||
        !config.alignment || off % config.alignment || n % config.alignment)
        return "invalid-transport-request";
    if (s->calls == 2) {
        if (fault("read")) return "read";
        if (fault("timeout")) return "timeout";
        if (fault("cancel")) { raise(SIGTERM); return "cancelled"; }
        if (fault("crash")) raise(SIGKILL);
    }
    for (size_t i = 0; i < n; i++) {
        uint64_t address = off + i;
        b[i] = (unsigned char)((address ^ (address >> 8) ^ (address >> 16) ^ (address >> 24)) & 255);
    }
    *received = n;
    if (s->calls == 2 && fault("short")) *received = n - 1;
    if (s->calls == 2 && fault("oversized")) *received = n + 1;
    return NULL;
}
const char *transport_close(struct session *s)
{
    s->opened = 0; s->resources = 0;
    if (fault("cleanup")) return "restoration-failed";
    /* No saved state is restored if the generation changed. */
    if (s->generation != 1) return "generation-changed-no-restore";
    return NULL;
}
