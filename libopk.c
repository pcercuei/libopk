
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "opk.h"
#include "unsqfs.h"

#define HEADER "[Desktop Entry]\n"
#define HEADER_LEN (sizeof(HEADER) - 1)

struct Entry {
	SLIST_ENTRY(Entry) next;
	char *name;
	char *value;
};

struct ParserData {
	SLIST_HEAD(Entries, Entry) head;
	struct PkgData *pdata;
	void *buf;
	void *buf_end;
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
		free(entry->name);
		free(entry->value);
		free(entry);
	}

	SLIST_INIT(&pdata->head);
}

static void skip_comments(struct ParserData *pdata)
{
	const char *curr = pdata->meta_curr;
	const void *end = pdata->buf_end;

	while (true) {
		if (curr == end) {
			break;
		} else if (*curr == '\n') {
			curr++;
		} else if (*curr == '#') {
			do { curr++; } while (curr != end && *curr != '\n');
		} else {
			break;
		}
	}

	pdata->meta_curr = curr;
}

static bool next_param(struct ParserData *pdata,
		const char **key_chars, size_t *key_size,
		const char **val_chars, size_t *val_size)
{
	skip_comments(pdata);
	const char *curr = pdata->meta_curr;
	const char *end = pdata->buf_end;

	// Check for end of metadata or end of "Desktop Entry" group.
	if (curr == end || *curr == '[') {
		*key_chars = *val_chars = NULL;
		*key_size = *val_size = 0;
		return true;
	}

	// Parse key.
	const char *key_start = curr;
	while (curr != end && *curr != '=' && *curr > ' ') curr++;
	*key_chars = key_start;
	*key_size = curr - key_start;

	// Skip whitespace.
	while (curr != end && (*curr == ' ' || *curr == '\t')) curr++;

	// Skip equals sign.
	if (curr != end && *curr == '=') {
		curr++;
	} else {
		return false;
	}

	// Skip whitespace.
	while (curr != end && (*curr == ' ' || *curr == '\t')) curr++;

	// Parse value.
	const char *val_start = curr;
	while (curr != end && *curr != '\n') curr++;
	*val_chars = val_start;
	*val_size = curr - val_start;

	// Save current position for next time.
	if (curr != end) curr++; // skip '\n'
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
		e->name  = strndup(key_chars, key_size);
		e->value = strndup(val_chars, val_size);
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
	void *buf;
	size_t buf_size;
	if (opk_sqfs_extract_file(pdata->pdata, name, &buf, &buf_size)) {
		return NULL;
	}
	pdata->buf = buf;
	pdata->buf_end = buf + buf_size;
	pdata->meta_curr = buf;

	/* Check for mandatory "Desktop Entry" group (acts as a kind of header) */
	skip_comments(pdata);
	if (pdata->meta_curr + HEADER_LEN > pdata->buf_end
			|| strncmp(pdata->meta_curr, HEADER, HEADER_LEN)) {
		fprintf(stderr, "%s: not a proper desktop entry file\n", name);
		return NULL;
	}
	pdata->meta_curr += HEADER_LEN;

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
