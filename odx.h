
#ifndef ODX_H
#define ODX_H

struct ParserData;

struct ParserData *openMetadata(const char *odx_filename);
void closeMetadata(struct ParserData *pdata);

char *readParam(struct ParserData *pdata, const char *name);

#endif /* ODX_H */
