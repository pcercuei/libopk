
#ifndef OPK_H
#define OPK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdlib.h>

struct OPK;

struct OPK *opk_open(const char *opk_filename);
void opk_close(struct OPK *opk);

const char *opk_open_metadata(struct OPK *opk);
bool opk_read_pair(struct OPK *opk,
		const char **key_chars, size_t *key_size,
		const char **val_chars, size_t *val_size);

void *opk_extract_file(struct OPK *opk, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* OPK_H */
