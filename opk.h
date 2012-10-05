
#ifndef OPK_H
#define OPK_H

struct ParserData;

struct ParserData *openMetadata(const char *opk_filename);
void closeMetadata(struct ParserData *pdata);

char *readParam(struct ParserData *pdata, const char *name);

#endif /* OPK_H */
