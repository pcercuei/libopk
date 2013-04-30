
#ifndef OPK_H
#define OPK_H

#ifdef __cplusplus
extern "C" {
#endif

struct OPK;

struct OPK *opk_open(const char *opk_filename);
void opk_close(struct OPK *opk);

const char *opk_open_metadata(struct OPK *opk);
char *opk_read_param(struct OPK *opk, const char *name);

void *opk_extract_file(struct OPK *opk, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* OPK_H */
