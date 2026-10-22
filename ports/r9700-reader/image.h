#ifndef R9700_IMAGE_H
#define R9700_IMAGE_H
#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#define IMAGE_SLOTS 16U
struct image_file { int fd; uint64_t size; struct stat initial; };
struct image_slot { uint64_t header, csm, directory, size; uint32_t type, version; };
struct image_layout { int ifwi; size_t count; struct image_slot slot[IMAGE_SLOTS]; };
int image_open(struct image_file *f, const char *path);
int image_read(const struct image_file *f, uint64_t offset, void *data, size_t length);
int image_stable(const struct image_file *f);
int image_layout(const struct image_file *f, struct image_layout *layout);
int image_sum(const struct image_file *f, uint64_t offset, uint64_t length,
              unsigned *sum, char sha[65]);
int image_commands(int argc, char **argv);
#endif
