
#ifndef ODX_H
#define ODX_H

#include <sys/queue.h>

struct Entry {
	SLIST_ENTRY(Entry) next;
	char *name;
	char *value;
};

struct ParserData {
	SLIST_HEAD(Entries, Entry) head;
	char *buf;
};

struct ParserData *openMetadata(const char *fn);
void closeMetadata(struct ParserData *pdata);

char *readParam(struct ParserData *pdata, const char *name);


#endif /* ODX_H */
