
#include <stdbool.h>
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
	void *buf;
	const void *meta_curr;
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

static bool next_param(struct ParserData *pdata,
		const char **key_chars, size_t *key_size,
		const char **val_chars, size_t *val_size)
{
	const char *curr = pdata->meta_curr;

	// Check for end of metadata.
	if (!*curr) {
		*key_chars = *val_chars = NULL;
		*key_size = *val_size = 0;
		return true;
	}

	// Parse key.
	const char *key_start = curr;
	while (*curr && *curr != '=') curr++;
	if (!*curr) return false;
	*key_chars = key_start;
	*key_size = curr - key_start;

	// Parse value.
	curr++; // skip '='
	const char *val_start = curr;
	while (*curr && *curr != '\n') curr++;
	*val_chars = val_start;
	*val_size = curr - val_start;

	// Save current position for next time.
	if (*curr) curr++; // skip '\n'
	pdata->meta_curr = curr;
	return true;
}

static bool parse_params(struct ParserData *pdata)
{
	while (true) {
		// Parse key-value pair.
		const char *key_chars, *val_chars;
		size_t key_size, val_size;
		if (!next_param(pdata, &key_chars, &key_size, &val_chars, &val_size)) {
			fprintf(stderr, "Error reading metadata\n");
			list_free(pdata);
			return false;
		}
		if (!key_chars) {
			return true;
		}

		// Insert key-value pair into linked list.
		struct Entry *e = malloc(sizeof(*e));
		((char *)key_chars)[key_size] = '\0';
		e->name = (char *)key_chars;
		((char *)val_chars)[val_size] = '\0';
		e->value = (char *)val_chars;
		SLIST_INSERT_HEAD(&pdata->head, e, next);
	}
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
	pdata->meta_curr = buf + sizeof(HEADER);

	pdata->buf = buf;
	if (!parse_params(pdata)) {
		return NULL;
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

void *opk_extract_file(struct ParserData *pdata, const char *name)
{
	void *data;
	size_t size;
	if (opk_sqfs_extract_file(pdata->pdata, name, &data, &size)) {
		return NULL;
	} else {
		return data;
	}
}
