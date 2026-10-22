#include "reader.h"
int read_window(const struct geometry *g, uint64_t off, uint64_t len,
                uint64_t *start, size_t *wire, size_t *skip, size_t *useful)
{
    if (!g->positive_id || !g->complete_topology || !g->capacity ||
        g->capacity > CAPACITY_LIMIT || !g->alignment ||
        g->alignment > BUFFER_SIZE || !g->max_transfer ||
        g->max_transfer > BUFFER_SIZE || g->max_transfer < g->alignment ||
        g->max_transfer % g->alignment || g->capacity % g->alignment ||
        off > g->capacity || !len || len > g->capacity - off) return -1;
    *start = off - off % g->alignment;
    *skip = (size_t)(off - *start);
    uint64_t available = g->capacity - *start;
    size_t n = available < g->max_transfer ? (size_t)available : g->max_transfer;
    size_t take = n - *skip;
    if (len < take) take = (size_t)len;
    *useful = take;
    size_t end = *skip + take;
    *wire = end + (g->alignment - end % g->alignment) % g->alignment;
    return 0;
}
