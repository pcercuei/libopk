
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "odx.h"

#define METADATA_FN "METADATA.desktop"
#define HEADER "[Desktop Entry]"

char *unsquashfs_single_file(const char *image_name, const char *file_name);

struct Entry {
	SLIST_ENTRY(Entry) next;
	char *name;
	char *value;
};

struct ParserData {
	SLIST_HEAD(Entries, Entry) head;
	char *buf;
};

struct ParserData *openMetadata(const char *odx_filename)
{
	struct ParserData *pdata;
	char *buf;

	/* Extract the meta-data from the OD package */
	buf = unsquashfs_single_file(odx_filename, METADATA_FN);
	if (!buf)
		return NULL;

	/* Check for standard .desktop header */
	if (strncmp(buf, HEADER, sizeof(HEADER) - 1)) {
		fprintf(stderr, "Unrecognized metadata\n");
		free(buf);
		return NULL;
	}

	pdata = malloc(sizeof(*pdata));
	pdata->buf = buf;
	SLIST_INIT(&pdata->head);

	buf += sizeof(HEADER);

	/* Insert all the name=value couples found
	 * on a linked list */
	while(buf[0]) {
		struct Entry *e;

		e = malloc(sizeof(*e));
		e->name = buf;

		while(buf[0] && (buf[0] != '='))
			buf++;

		if (!buf[0]) {
			fprintf(stderr, "Error reading metadata\n");
			free(e);
			closeMetadata(pdata);
			return NULL;
		}

		buf[0] = '\0';
		e->value = ++buf;

		while(buf[0] && (buf[0] != '\n'))
			buf++;

		SLIST_INSERT_HEAD(&pdata->head, e, next);

		if (buf[0])
			(buf++)[0] = '\0';
		else
			break;
	}

	return pdata;
}

void closeMetadata(struct ParserData *pdata)
{
	while (!SLIST_EMPTY(&pdata->head)) {
		struct Entry *entry = SLIST_FIRST(&pdata->head);
		SLIST_REMOVE_HEAD(&pdata->head, next);
		free(entry);
	}

	free(pdata->buf);
	free(pdata);
}

char *readParam(struct ParserData *pdata, const char *name)
{
	struct Entry *entry;

	/* Iterate on the linked list to find the
	 * corresponding parameter, and return its value */
	SLIST_FOREACH(entry, &pdata->head, next) {
		if (!strcmp(name, entry->name))
			return entry->value;
	}

	return NULL;
}
