
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "opk.h"
#include "unsqfs.h"

#define HEADER "[Desktop Entry]"

struct Entry {
	SLIST_ENTRY(Entry) next;
	char *name;
	char *value;
};

struct ParserData {
	SLIST_HEAD(Entries, Entry) head;
	struct PkgData *pdata;
	char *buf;
};

struct ParserData *opk_open(const char *opk_filename)
{
	struct ParserData *pdata = malloc(sizeof(*pdata));
	if (!pdata)
		return NULL;

	pdata->pdata = opk_sqfs_open(opk_filename);
	if (!pdata->pdata) {
		free(pdata);
		return NULL;
	}

	pdata->buf = NULL;
	SLIST_INIT(&pdata->head);

	return pdata;
}

static void list_free(struct ParserData *pdata)
{
	while (!SLIST_EMPTY(&pdata->head)) {
		struct Entry *entry = SLIST_FIRST(&pdata->head);
		SLIST_REMOVE_HEAD(&pdata->head, next);
		free(entry);
	}

	SLIST_INIT(&pdata->head);
}

const char *opk_open_metadata(struct ParserData *pdata)
{
	/* Free previous meta-data information */
	list_free(pdata);
	if (pdata->buf)
		free(pdata->buf);
	pdata->buf = NULL;

	/* Get the name of the next .desktop */
	const char *name = opk_sqfs_get_metadata(pdata->pdata);
	if (!name)
		return NULL;

	/* Extract the meta-data from the OD package */
	char *buf = opk_extract_file(pdata, name);
	if (!buf)
		return NULL;

	/* Check for standard .desktop header */
	if (strncmp(buf, HEADER, sizeof(HEADER) - 1)) {
		fprintf(stderr, "Unrecognized metadata\n");
		free(buf);
		return NULL;
	}

	pdata->buf = buf;

	buf += sizeof(HEADER);

	/* Insert all the name=value couples found
	 * on a linked list */
	while(buf[0]) {
		struct Entry *e = malloc(sizeof(*e));
		e->name = buf;

		while(buf[0] && (buf[0] != '='))
			buf++;

		if (!buf[0]) {
			fprintf(stderr, "Error reading metadata\n");
			free(e);
			list_free(pdata);
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

	return name;
}

void opk_close(struct ParserData *pdata)
{
	opk_sqfs_close(pdata->pdata);

	list_free(pdata);

	if (pdata->buf)
		free(pdata->buf);
	free(pdata);
}

char *opk_read_param(struct ParserData *pdata, const char *name)
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

char *opk_extract_file(struct ParserData *pdata, const char *name)
{
	return opk_sqfs_extract_file(pdata->pdata, name);
}
