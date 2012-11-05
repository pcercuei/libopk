
#ifndef OPK_H
#define OPK_H

#ifdef __cplusplus
extern "C" {
#endif

struct ParserData;

struct ParserData *opk_open(const char *opk_filename);
void opk_close(struct ParserData *pdata);

char *opk_read_param(struct ParserData *pdata, const char *name);

char *opk_extract_file(struct ParserData *pdata, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* OPK_H */
