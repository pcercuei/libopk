
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

// Public interface.
#pragma GCC visibility push(default)
#include "opk.h"
#pragma GCC visibility pop

// Internal interfaces.
#include "unsqfs.h"

#define HEADER "[Desktop Entry]\n"
#define HEADER_LEN (sizeof(HEADER) - 1)

struct OPK {
	struct PkgData *pdata;
	void *buf;
	void *buf_end;
	const void *meta_curr;
};

struct OPK *opk_open(const char *opk_filename)
{
	struct OPK *opk = malloc(sizeof(*opk));
	if (!opk)
		return NULL;

	opk->pdata = opk_sqfs_open(opk_filename);
	if (!opk->pdata) {
		free(opk);
		return NULL;
	}

	opk->buf = NULL;

	return opk;
}

static void skip_comments(struct OPK *opk)
{
	const char *curr = opk->meta_curr;
	const void *end = opk->buf_end;

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

	opk->meta_curr = curr;
}

bool opk_read_pair(struct OPK *opk,
		const char **key_chars, size_t *key_size,
		const char **val_chars, size_t *val_size)
{
	skip_comments(opk);
	const char *curr = opk->meta_curr;
	const char *end = opk->buf_end;

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
	opk->meta_curr = curr;
	return true;
}

const char *opk_open_metadata(struct OPK *opk)
{
	/* Free previous meta-data information */
	if (opk->buf)
		free(opk->buf);
	opk->buf = NULL;

	/* Get the name of the next .desktop */
	const char *name = opk_sqfs_get_metadata(opk->pdata);
	if (!name)
		return NULL;

	/* Extract the meta-data from the OD package */
	void *buf;
	size_t buf_size;
	if (opk_sqfs_extract_file(opk->pdata, name, &buf, &buf_size)) {
		return NULL;
	}
	opk->buf = buf;
	opk->buf_end = buf + buf_size;
	opk->meta_curr = buf;

	/* Check for mandatory "Desktop Entry" group (acts as a kind of header) */
	skip_comments(opk);
	if (opk->meta_curr + HEADER_LEN > opk->buf_end
			|| strncmp(opk->meta_curr, HEADER, HEADER_LEN)) {
		fprintf(stderr, "%s: not a proper desktop entry file\n", name);
		return NULL;
	}
	opk->meta_curr += HEADER_LEN;

	return name;
}

void opk_close(struct OPK *opk)
{
	opk_sqfs_close(opk->pdata);

	if (opk->buf)
		free(opk->buf);
	free(opk);
}

void *opk_extract_file(struct OPK *opk, const char *name)
{
	void *data;
	size_t size;
	if (opk_sqfs_extract_file(opk->pdata, name, &data, &size)) {
		return NULL;
	} else {
		return data;
	}
}
