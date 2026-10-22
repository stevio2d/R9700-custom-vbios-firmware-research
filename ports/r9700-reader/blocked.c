#include "reader.h"
const int transport_synthetic = 0;
const char *transport_name = "unavailable-no-qualified-protocol";
void transport_configure(const struct options *o) { (void)o; }
const char *transport_open(const char *b, struct session *s)
{ (void)b; (void)s; return "live-disabled-protocol-and-kernel-unqualified"; }
const char *transport_identify(struct session *s, struct geometry *g)
{ (void)s; (void)g; return "live-disabled"; }
const char *transport_check(struct session *s) { (void)s; return "live-disabled"; }
const char *transport_read(struct session *s, uint64_t o, size_t n, unsigned char *b, size_t *r)
{ (void)s; (void)o; (void)n; (void)b; (void)r; return "live-disabled"; }
const char *transport_close(struct session *s) { (void)s; return "live-disabled"; }
