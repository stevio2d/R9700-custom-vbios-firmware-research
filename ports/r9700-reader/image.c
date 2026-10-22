#define _GNU_SOURCE
#include "image.h"
#include "reader.h"
#include "record.h"
#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint16_t u16(const unsigned char *p)
{ return (uint16_t)((unsigned)p[0] | (unsigned)p[1] << 8); }
static uint32_t u32(const unsigned char *p)
{ return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t u64(const unsigned char *p)
{ return u32(p) | (uint64_t)u32(p+4) << 32; }
static int range(uint64_t offset, uint64_t length, uint64_t limit)
{ return offset <= limit && length <= limit - offset; }
int image_open(struct image_file *f, const char *path)
{
    f->fd = open_regular(AT_FDCWD,path);
    if (f->fd < 0) return -1;
    if (fstat(f->fd,&f->initial) || f->initial.st_size < 0 ||
        (uint64_t)f->initial.st_size > CAPACITY_LIMIT) {
        close(f->fd); f->fd = -1; return -1;
    }
    f->size = (uint64_t)f->initial.st_size;
    return 0;
}
int image_read(const struct image_file *f, uint64_t offset, void *data, size_t length)
{
    unsigned char *p = data;
    if (!range(offset,length,f->size)) return -1;
    while (length) {
        ssize_t n = pread(f->fd,p,length,(off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        offset += (uint64_t)n; length -= (size_t)n; p += (size_t)n;
    }
    return 0;
}
int image_stable(const struct image_file *f)
{
    struct stat s;
    if (fstat(f->fd,&s)) return -1;
    return s.st_size != f->initial.st_size ||
        s.st_mtim.tv_sec != f->initial.st_mtim.tv_sec || s.st_mtim.tv_nsec != f->initial.st_mtim.tv_nsec ||
        s.st_ctim.tv_sec != f->initial.st_ctim.tv_sec || s.st_ctim.tv_nsec != f->initial.st_ctim.tv_nsec ? -1 : 0;
}
int image_layout(const struct image_file *f, struct image_layout *layout)
{
    unsigned char header[0x54], dir[16], entry[16], slot[32];
    memset(layout,0,sizeof(*layout));
    if (image_read(f,0,header,4)) return -1;
    if (u32(header) != UINT32_C(0x55aa55aa)) {
        if (header[0] != 0x55 || header[1] != 0xaa) return -1;
        layout->count = 1;
        return 0;
    }
    layout->ifwi = 1;
    if (image_read(f,0,header,sizeof(header))) return -1;
    uint64_t table = u32(header+0x14);
    if (image_read(f,table,dir,sizeof(dir)) || memcmp(dir,"$PSP",4)) return -1;
    uint32_t count = u32(dir+8);
    if (!count || count > IMAGE_SLOTS || !range(table+16,(uint64_t)count*16,f->size)) return -1;
    layout->count = count;
    for (size_t i = 0; i < count; i++) {
        if (image_read(f,table+16+i*16,entry,sizeof(entry)) || u32(entry+4) != sizeof(slot)) return -1;
        struct image_slot *s = &layout->slot[i];
        s->type = u32(entry); s->header = u64(entry+8);
        if (image_read(f,s->header,slot,sizeof(slot))) return -1;
        s->version = u32(slot+0xc); s->directory = u32(slot+0x10);
        s->size = u32(slot+0x18); s->csm = u32(slot+0x1c);
        if (!s->size || !range(s->directory,s->size,f->size) ||
            s->csm < s->directory || !range(s->csm,0x70,s->directory+s->size)) return -1;
        for (size_t j = 0; j < i; j++) {
            const struct image_slot *p = &layout->slot[j];
            if (s->directory < p->directory+p->size && p->directory < s->directory+s->size) return -1;
        }
    }
    return 0;
}
int image_sum(const struct image_file *f, uint64_t offset, uint64_t length,
              unsigned *sum, char sha[65])
{
    unsigned char buf[BUFFER_SIZE], hash[32]; unsigned int n = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int error = !range(offset,length,f->size) || EVP_DigestInit_ex(ctx,EVP_sha256(),NULL) != 1;
    *sum = 0;
    while (!error && length) {
        size_t size = length > sizeof(buf) ? sizeof(buf) : (size_t)length;
        if (image_read(f,offset,buf,size) || EVP_DigestUpdate(ctx,buf,size) != 1) { error = 1; break; }
        for (size_t i = 0; i < size; i++) *sum = (*sum + buf[i]) & 65535U;
        offset += size; length -= size;
    }
    if (!error && (EVP_DigestFinal_ex(ctx,hash,&n) != 1 || n != 32)) error = 1;
    EVP_MD_CTX_free(ctx);
    if (error) return -1;
    for (size_t i = 0; i < 32; i++) (void)snprintf(sha+2*i,3,"%02x",hash[i]);
    return image_stable(f);
}
static int legacy_header(const struct image_file *f, const struct image_slot *slot,
                         unsigned char header[0x70], uint64_t *length)
{
    if (image_read(f,slot->csm,header,0x70) || header[0] != 0x55 || header[1] != 0xaa || !header[2]) return -1;
    *length = (uint64_t)header[2]*512;
    uint64_t end = slot->size ? slot->directory+slot->size : f->size;
    return range(slot->csm,*length,end) ? 0 : -1;
}
static int part_number(const struct image_file *f, const struct image_slot *slot, char out[256])
{
    unsigned char header[0x70], atom[0x22], buf[256]; uint64_t length;
    if (legacy_header(f,slot,header,&length)) return -1;
    uint64_t end = slot->csm+length;
    uint16_t at = u16(header+0x48), msg = u16(header+0x6e);
    if (!at || !msg || !range(slot->csm+at,sizeof(atom),end) ||
        image_read(f,slot->csm+at,atom,sizeof(atom)) || memcmp(atom+4,"ATOM",4) ||
        u16(atom)<sizeof(atom) || !range(slot->csm+at,u16(atom),end)) return -1;
    uint16_t config = u16(atom+0xc);
    if (config <= msg || !range(slot->csm+msg,(uint64_t)config-msg,end)) return -1;
    size_t n = (size_t)config-msg;
    if (n > sizeof(buf)) n = sizeof(buf);
    if (image_read(f,slot->csm+msg,buf,n)) return -1;
    for (size_t i = 0; i < n; i++) {
        if (!buf[i]) { if (!i) return -1; out[i] = 0; return 0; }
        if (buf[i]<32 || buf[i]>126) return -1;
        out[i] = (char)buf[i];
    }
    return -1;
}
static void json_string(const char *s)
{
    putchar('"');
    for (; *s; s++) { if (*s == '"' || *s == '\\') putchar('\\'); putchar((unsigned char)*s); }
    putchar('"');
}
static int inspect(const struct image_file *f)
{
    struct image_layout l;
    if (image_layout(f,&l)) return -1;
    struct facts { uint64_t length, pcir, atom; unsigned vendor, device, code, last, format, content; char pn[256]; } facts[IMAGE_SLOTS] = {{0}};
    for (size_t i = 0; i < l.count; i++) {
        unsigned char header[0x70], pcir[0x16], atom[0x22];
        struct facts *p = &facts[i];
        if (legacy_header(f,&l.slot[i],header,&p->length)) return -1;
        uint64_t base = l.slot[i].csm, end = base+p->length;
        p->pcir = base+u16(header+0x18);
        if (u16(header+0x18) < 0x1a || !range(p->pcir,sizeof(pcir),end) ||
            image_read(f,p->pcir,pcir,sizeof(pcir)) || memcmp(pcir,"PCIR",4) ||
            u16(pcir+0xa) < sizeof(pcir) || !range(p->pcir,u16(pcir+0xa),end)) return -1;
        p->vendor = u16(pcir+4); p->device = u16(pcir+6); p->code = pcir[0x14]; p->last = (pcir[0x15] >> 7) & 1U;
        uint16_t at = u16(header+0x48);
        if (at) {
            p->atom = base+at;
            if (!range(p->atom,sizeof(atom),end) || image_read(f,p->atom,atom,sizeof(atom)) ||
                memcmp(atom+4,"ATOM",4) || u16(atom)<sizeof(atom) || !range(p->atom,u16(atom),end)) return -1;
            p->format = atom[2]; p->content = atom[3];
        }
        if (part_number(f,&l.slot[i],p->pn)) p->pn[0] = 0;
    }
    unsigned sum; char sha[65];
    if (image_sum(f,0,f->size,&sum,sha)) return -1;
    printf("{\"classification\":\"file\",\"physical_backup_verified\":false,\"size\":%" PRIu64 ",\"sha256\":\"%s\",\"format\":\"%s\",\"active_partition\":null,\"running_firmware_versions\":null,\"slots\":[",f->size,sha,l.ifwi ? "ifwi" : "vbios");
    for (size_t i = 0; i < l.count; i++) {
        const struct image_slot *s = &l.slot[i]; const struct facts *p = &facts[i];
        printf("%s{\"index\":%zu,\"csm_offset\":%" PRIu64 ",\"vbios_length\":%" PRIu64 ",\"directory_offset\":%" PRIu64 ",\"partition_length\":%" PRIu64 ",\"slot_version_raw\":%u,\"pcir_offset\":%" PRIu64 ",\"vendor\":%u,\"device\":%u,\"code_type\":%u,\"last_image\":%s,\"atom_offset\":%" PRIu64 ",\"atom_format\":%u,\"atom_content\":%u,\"part_number\":",i ? "," : "",i,s->csm,p->length,s->directory,s->size,s->version,p->pcir,p->vendor,p->device,p->code,p->last ? "true" : "false",p->atom,p->format,p->content);
        if (*p->pn) json_string(p->pn); else fputs("null",stdout);
        putchar('}');
    }
    puts("],\"limitations\":[\"first legacy image per slot; EFI and PSP component bodies are not decoded\",\"layout and raw stored version fields do not establish boot selection or authenticity\"]}");
    return 0;
}
static int compare_usage(void)
{
    fputs("usage: compare --kind part-number|partition --left FILE --right FILE [--left-slot N --right-slot N]\n",stderr);
    return 2;
}
static int compare_files(int argc, char **argv)
{
    const char *left = NULL, *right = NULL, *kind = NULL;
    uint64_t ls = 0, rs = 0; unsigned seen = 0;
    for (int i = 2; i < argc; i += 2) {
        if (i+1 >= argc) return compare_usage();
        unsigned bit;
        if (!strcmp(argv[i],"--left")) { bit = 1; left = argv[i+1]; }
        else if (!strcmp(argv[i],"--right")) { bit = 2; right = argv[i+1]; }
        else if (!strcmp(argv[i],"--kind")) { bit = 4; kind = argv[i+1]; }
        else if (!strcmp(argv[i],"--left-slot")) { bit = 8; if (parse_u64(argv[i+1],&ls)) return compare_usage(); }
        else if (!strcmp(argv[i],"--right-slot")) { bit = 16; if (parse_u64(argv[i+1],&rs)) return compare_usage(); }
        else return compare_usage();
        if (seen & bit) return compare_usage();
        seen |= bit;
    }
    if (!left || !right || !kind || (strcmp(kind,"part-number") && strcmp(kind,"partition"))) return compare_usage();
    struct image_file a = {.fd=-1}, b = {.fd=-1};
    struct image_layout la, lb; char pa[256], pb[256], ha[65], hb[65];
    int error = image_open(&a,left) || image_open(&b,right);
    if (!error) error = image_layout(&a,&la) || image_layout(&b,&lb) || ls >= la.count || rs >= lb.count;
    int match = 0;
    if (!error && !strcmp(kind,"part-number")) {
        error = part_number(&a,&la.slot[ls],pa) || part_number(&b,&lb.slot[rs],pb);
        if (!error) {
            match = 1;
            for (size_t i = 0; i < 10; i++) {
                unsigned char ca = (unsigned char)pa[i], cb = (unsigned char)pb[i];
                if (ca >= 'a' && ca <= 'z') ca = (unsigned char)(ca-'a'+'A');
                if (cb >= 'a' && cb <= 'z') cb = (unsigned char)(cb-'a'+'A');
                if (ca != cb) { match = 0; break; }
                if (!ca || !cb) break;
            }
        }
    }
    else if (!error) {
        unsigned sum;
        if (!la.ifwi || !lb.ifwi) error = 1;
        else error = image_sum(&a,la.slot[ls].directory,la.slot[ls].size,&sum,ha) ||
                     image_sum(&b,lb.slot[rs].directory,lb.slot[rs].size,&sum,hb);
        if (!error) match = la.slot[ls].size == lb.slot[rs].size && !strcmp(ha,hb);
    }
    if (a.fd >= 0) { if (image_stable(&a)) error = 1; if (close(a.fd)) error = 1; }
    if (b.fd >= 0) { if (image_stable(&b)) error = 1; if (close(b.fd)) error = 1; }
    if (error) { fputs("file-comparison: malformed, changed or unavailable field\n",stderr); return 1; }
    printf("{\"classification\":\"file\",\"kind\":\"%s\",\"left_slot\":%" PRIu64 ",\"right_slot\":%" PRIu64 ",\"active_partition\":null,\"equal\":%s,",kind,ls,rs,match ? "true" : "false");
    if (!strcmp(kind,"part-number")) {
        fputs("\"algorithm\":\"ascii-casefold-prefix-10\",\"left\":",stdout); json_string(pa);
        fputs(",\"right\":",stdout); json_string(pb);
        puts(",\"limitation\":\"ASCII part numbers; retained default comparison length\"}");
    }
    else printf("\"algorithm\":\"sha256\",\"left_offset\":%" PRIu64 ",\"left_length\":%" PRIu64 ",\"right_offset\":%" PRIu64 ",\"right_length\":%" PRIu64 ",\"left_sha256\":\"%s\",\"right_sha256\":\"%s\"}\n",la.slot[ls].directory,la.slot[ls].size,lb.slot[rs].directory,lb.slot[rs].size,ha,hb);
    return match ? 0 : 1;
}
static int file_usage(void)
{
    fputs("usage: inspect --file FILE | checksum --file FILE [--scope windows-file|vbios|rom-default|complete|region] [--slot N] [--offset N --length N] [--expect DECIMAL]\n",stderr);
    return 2;
}
int image_commands(int argc, char **argv)
{
    if (!strcmp(argv[1],"compare")) return compare_files(argc,argv);
    int is_inspect = !strcmp(argv[1],"inspect");
    const char *path = NULL, *scope = NULL;
    uint64_t slot = 0, offset = 0, length = 0, expected = 0;
    unsigned seen = 0;
    for (int i = 2; i < argc; i += 2) {
        if (i+1 >= argc) return file_usage();
        unsigned bit;
        if (!strcmp(argv[i],"--file")) { bit = 1; path = argv[i+1]; }
        else if (!is_inspect && !strcmp(argv[i],"--scope")) { bit = 2; scope = argv[i+1]; }
        else if (!is_inspect && !strcmp(argv[i],"--slot")) { bit = 4; if (parse_u64(argv[i+1],&slot)) return file_usage(); }
        else if (!is_inspect && !strcmp(argv[i],"--offset")) { bit = 8; if (parse_u64(argv[i+1],&offset)) return file_usage(); }
        else if (!is_inspect && !strcmp(argv[i],"--length")) { bit = 16; if (parse_u64(argv[i+1],&length)) return file_usage(); }
        else if (!is_inspect && !strcmp(argv[i],"--expect")) { bit = 32; if (parse_u64(argv[i+1],&expected) || expected > 65535) return file_usage(); }
        else return file_usage();
        if (seen & bit) return file_usage();
        seen |= bit;
    }
    if (!path) return file_usage();
    if (!scope) scope = "windows-file";
    int complete = !strcmp(scope,"complete"), region = !strcmp(scope,"region");
    if (!is_inspect && (!complete && !region && strcmp(scope,"windows-file") && strcmp(scope,"vbios") && strcmp(scope,"rom-default"))) return file_usage();
    if (!is_inspect && (region ? (seen & 28U) != 24U || !length : (seen & 24U) != 0)) return file_usage();
    if (complete && (seen & 4U)) return file_usage();
    struct image_file f = {.fd = -1};
    if (image_open(&f,path)) { fputs("file-open: regular bounded input required\n",stderr); return 1; }
    int error = 0, mismatch = 0;
    if (is_inspect) error = inspect(&f);
    else {
        if (complete) length = f.size;
        else if (!region) {
            struct image_layout l; unsigned char header[0x70]; uint64_t bios_length;
            if (image_layout(&f,&l) || slot >= l.count || legacy_header(&f,&l.slot[slot],header,&bios_length)) error = 1;
            else {
                offset = l.slot[slot].csm;
                if (!strcmp(scope,"windows-file")) {
                    unsigned char first[3];
                    if (image_read(&f,0,first,sizeof(first))) error = 1;
                    else length = (uint64_t)first[2]*512;
                }
                else if (!strcmp(scope,"vbios")) length = bios_length;
                else length = (bios_length+65535U) & ~UINT64_C(65535);
                uint64_t limit = l.slot[slot].size ? l.slot[slot].directory+l.slot[slot].size : f.size;
                if (!range(offset,length,limit)) error = 1;
            }
        }
        unsigned sum = 0; char sha[65];
        if (!error) error = image_sum(&f,offset,length,&sum,sha);
        if (!error) {
            mismatch = (seen & 32U) && sum != expected;
            printf("{\"classification\":\"file\",\"algorithm\":\"byte-sum-mod-65536\",\"scope\":\"%s\",\"offset\":%" PRIu64 ",\"length\":%" PRIu64 ",\"checksum\":%u,\"sha256\":\"%s\",\"matches_expected\":%s}\n",scope,offset,length,sum,sha,seen & 32U ? (mismatch ? "false" : "true") : "null");
        }
    }
    if (image_stable(&f)) error = 1;
    if (close(f.fd)) error = 1;
    if (error) { fputs("file-analysis: malformed, truncated, changed or out-of-range input\n",stderr); return 1; }
    return mismatch ? 1 : 0;
}
