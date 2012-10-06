
#ifndef OPK_H
#define OPK_H

#ifdef __cplusplus
extern "C" {
#endif

struct ParserData;

struct ParserData *openMetadata(const char *opk_filename);
void closeMetadata(struct ParserData *pdata);

char *readParam(struct ParserData *pdata, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* OPK_H */
