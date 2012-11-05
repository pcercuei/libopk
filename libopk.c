
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "opk.h"
#include "unsqfs.h"

#define METADATA_FN "METADATA.desktop"
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
	struct ParserData *pdata;
	char *buf;

	pdata = malloc(sizeof(*pdata));
	if (!pdata)
		return NULL;

	pdata->pdata = opk_sqfs_open(opk_filename);
	if (!pdata->pdata)
		goto err_free_parserdata;

	/* Extract the meta-data from the OD package */
	buf = opk_extract_file(pdata, METADATA_FN);
	if (!buf)
		goto err_free_pkgdata;

	/* Check for standard .desktop header */
	if (strncmp(buf, HEADER, sizeof(HEADER) - 1)) {
		fprintf(stderr, "Unrecognized metadata\n");
		goto err_free_buf;
	}

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
			opk_close(pdata);
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

err_free_buf:
	free(buf);
err_free_pkgdata:
	free(pdata->pdata);
err_free_parserdata:
	free(pdata);
	return NULL;
}

void opk_close(struct ParserData *pdata)
{
	opk_sqfs_close(pdata->pdata);

	while (!SLIST_EMPTY(&pdata->head)) {
		struct Entry *entry = SLIST_FIRST(&pdata->head);
		SLIST_REMOVE_HEAD(&pdata->head, next);
		free(entry);
	}

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
