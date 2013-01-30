/*
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011
 * Phillip Lougher <phillip@lougher.demon.co.uk>
 *
 * Copyright (c) 2010 LG Electronics
 * Chan Jeong <chan.jeong@lge.com>
 *
 * Copyright (c) 2012 Reality Diluted, LLC
 * Steven J. Hill <sjhill@realitydiluted.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * unsqfs.c
 *
 * Unsquash a squashfs filesystem with minimal support. This code is
 * for little endian only, ignores uid/gid, ignores xattr, only works
 * for squashfs version >4.0, only supports zlib and lzo compression,
 * is only for Linux, is not multi-threaded and does not support any
 * regular expressions. You have been warned.
 *    -Steve
 *
 * To build as a part of a library or application compile this file
 * and link with the following CFLAGS and LDFLAGS:
 *
 *    CFLAGS += -O2 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
 *    LDFLAGS += -lz -llzo2
 */

#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#if USE_GZIP
#include <zlib.h>
#endif
#if USE_LZO
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#endif

#include "unsqfs.h"

#define SQUASHFS_MAGIC			0x73717368
#define SQUASHFS_START			0

/* size of metadata (inode and directory) blocks */
#define SQUASHFS_METADATA_SIZE		8192

/* default size of data blocks */
#define SQUASHFS_FILE_SIZE		131072
#define SQUASHFS_FILE_MAX_SIZE		1048576

/* Max length of filename (not 255) */
#define SQUASHFS_NAME_LEN		256

#define SQUASHFS_INVALID_FRAG		((unsigned int) 0xffffffff)

/* Max number of types and file types */
#define SQUASHFS_DIR_TYPE		1
#define SQUASHFS_REG_TYPE		2
#define SQUASHFS_LDIR_TYPE		8
#define SQUASHFS_LREG_TYPE		9

/* Flag whether block is compressed or uncompressed, bit is set if block is
 * uncompressed */
#define SQUASHFS_COMPRESSED_BIT		(1 << 15)

#define SQUASHFS_COMPRESSED_SIZE(B)	(((B) & ~SQUASHFS_COMPRESSED_BIT) ? \
		(B) & ~SQUASHFS_COMPRESSED_BIT :  SQUASHFS_COMPRESSED_BIT)

#define SQUASHFS_COMPRESSED(B)		(!((B) & SQUASHFS_COMPRESSED_BIT))

#define SQUASHFS_COMPRESSED_BIT_BLOCK		(1 << 24)

#define SQUASHFS_COMPRESSED_SIZE_BLOCK(B)	((B) & \
	~SQUASHFS_COMPRESSED_BIT_BLOCK)

#define SQUASHFS_COMPRESSED_BLOCK(B)	(!((B) & SQUASHFS_COMPRESSED_BIT_BLOCK))

/*
 * Inode number ops.  Inodes consist of a compressed block number, and an
 * uncompressed  offset within that block
 */
#define SQUASHFS_INODE_BLK(a)		((unsigned int) ((a) >> 16))

#define SQUASHFS_INODE_OFFSET(a)	((unsigned int) ((a) & 0xffff))

/* fragment and fragment table defines */
#define SQUASHFS_FRAGMENT_BYTES(A)	((A) * sizeof(struct squashfs_fragment_entry))

#define SQUASHFS_FRAGMENT_INDEX(A)	(SQUASHFS_FRAGMENT_BYTES(A) / \
					SQUASHFS_METADATA_SIZE)

#define SQUASHFS_FRAGMENT_INDEX_OFFSET(A)	(SQUASHFS_FRAGMENT_BYTES(A) % \
						SQUASHFS_METADATA_SIZE)

#define SQUASHFS_FRAGMENT_INDEXES(A)	((SQUASHFS_FRAGMENT_BYTES(A) + \
					SQUASHFS_METADATA_SIZE - 1) / \
					SQUASHFS_METADATA_SIZE)

#define SQUASHFS_FRAGMENT_INDEX_BYTES(A)	(SQUASHFS_FRAGMENT_INDEXES(A) *\
						sizeof(long long))

/*
 * definitions for structures on disk
 */

typedef long long		squashfs_block;
typedef long long		squashfs_inode;

#define ZLIB_COMPRESSION	1
#define LZO_COMPRESSION		3

struct squashfs_super_block {
	unsigned int		s_magic;
	unsigned int		inodes;
	unsigned int		mkfs_time /* time of filesystem creation */;
	unsigned int		block_size;
	unsigned int		fragments;
	unsigned short		compression;
	unsigned short		block_log;
	unsigned short		flags;
	unsigned short		res0;
	unsigned short		s_major;
	unsigned short		s_minor;
	squashfs_inode		root_inode;
	long long		bytes_used;
	long long		res1;
	long long		res2;
	long long		inode_table_start;
	long long		directory_table_start;
	long long		fragment_table_start;
	long long		res3;
};

struct squashfs_dir_index {
	unsigned int		index;
	unsigned int		start_block;
	unsigned int		size;
	unsigned char		name[0];
};

struct squashfs_base_inode_header {
	unsigned short		inode_type;
	unsigned short		mode;
	unsigned short		uid;
	unsigned short		guid;
	unsigned int		mtime;
	unsigned int 		inode_number;
};

struct squashfs_reg_inode_header {
	unsigned short		inode_type;
	unsigned short		mode;
	unsigned short		uid;
	unsigned short		guid;
	unsigned int		mtime;
	unsigned int 		inode_number;
	unsigned int		start_block;
	unsigned int		fragment;
	unsigned int		offset;
	unsigned int		file_size;
	unsigned int		block_list[0];
};

struct squashfs_lreg_inode_header {
	unsigned short		inode_type;
	unsigned short		mode;
	unsigned short		uid;
	unsigned short		guid;
	unsigned int		mtime;
	unsigned int 		inode_number;
	squashfs_block		start_block;
	long long			file_size;
	long long			sparse;
	unsigned int		nlink;
	unsigned int		fragment;
	unsigned int		offset;
	unsigned int		xattr;
	unsigned int		block_list[0];
};

struct squashfs_dir_inode_header {
	unsigned short		inode_type;
	unsigned short		mode;
	unsigned short		uid;
	unsigned short		guid;
	unsigned int		mtime;
	unsigned int 		inode_number;
	unsigned int		start_block;
	unsigned int		nlink;
	unsigned short		file_size;
	unsigned short		offset;
	unsigned int		parent_inode;
};

struct squashfs_ldir_inode_header {
	unsigned short		inode_type;
	unsigned short		mode;
	unsigned short		uid;
	unsigned short		guid;
	unsigned int		mtime;
	unsigned int 		inode_number;
	unsigned int		nlink;
	unsigned int		file_size;
	unsigned int		start_block;
	unsigned int		parent_inode;
	unsigned short		i_count;
	unsigned short		offset;
	unsigned int		res0;
	struct squashfs_dir_index	index[0];
};

union squashfs_inode_header {
	struct squashfs_base_inode_header	base;
	struct squashfs_reg_inode_header	reg;
	struct squashfs_lreg_inode_header	lreg;
	struct squashfs_dir_inode_header	dir;
	struct squashfs_ldir_inode_header	ldir;
};

struct squashfs_dir_entry {
	unsigned short		offset;
	short			inode_number;
	unsigned short		type;
	unsigned short		size;
	char			name[0];
};

struct squashfs_dir_header {
	unsigned int		count;
	unsigned int		start_block;
	unsigned int		inode_number;
};

struct squashfs_fragment_entry {
	long long		start_block;
	unsigned int		size;
	unsigned int		unused;
};

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...) \
		do { \
			printf("\n"); \
			printf("unsquashfs: "s, ## args); \
		} while(0)
#else
#define TRACE(s, args...)
#endif

#define ERROR(s, args...) \
		do { \
			fprintf(stderr, "\n"); \
			fprintf(stderr, s, ## args); \
		} while(0)

#define CALCULATE_HASH(start)	(start & 0xffff)

struct hash_table_entry {
	long long	start;
	int		bytes;
	struct hash_table_entry *next;
};

struct inode {
	int blocks;
	unsigned int *block_ptr;
	long long data;
	int fragment;
	int frag_bytes;
	int inode_number;
	int mode;
	int offset;
	long long start;
	time_t time;
	int type;
};

/* default size of fragment buffer in Mbytes */
#define FRAGMENT_BUFFER_DEFAULT 256
/* default size of data buffer in Mbytes */
#define DATA_BUFFER_DEFAULT 256

#define DIR_ENT_SIZE	16

struct dir_ent	{
	char		name[SQUASHFS_NAME_LEN + 1];
	unsigned int	start_block;
	unsigned int	offset;
	unsigned int	type;
};

struct dir {
	int		dir_count;
	int 		cur_entry;
	unsigned int	mode;
	unsigned int	mtime;
	struct dir_ent	*dirs;
};

struct path_entry {
	char *name;
	struct pathname *paths;
};

struct pathname {
	int names;
	struct path_entry *name;
};

struct pathnames {
	int count;
	struct pathname *path[0];
};
#define PATHS_ALLOC_SIZE 10

struct PkgData {
	struct squashfs_super_block sBlk;
	union squashfs_inode_header header;
	struct inode inode;

	struct squashfs_fragment_entry *fragment_table;
	struct hash_table_entry *inode_table_hash[65536],
							*directory_table_hash[65536];

	int fd;
	char *inode_table, *directory_table;

	struct dir *dir;
};

static const int lookup_type[] = {
	0,
	S_IFDIR,
	S_IFREG,
	S_IFLNK,
	S_IFBLK,
	S_IFCHR,
	S_IFIFO,
	S_IFSOCK,
	S_IFDIR,
	S_IFREG,
	S_IFLNK,
	S_IFBLK,
	S_IFCHR,
	S_IFIFO,
	S_IFSOCK
};


/* forward delcarations */
static bool read_fs_bytes(int fd, long long byte, int bytes, void *buff);
static int read_block(struct PkgData *pdata,
			long long start, long long *next, void *block);
static int lookup_entry(struct hash_table_entry *hash_table[], long long start);


static bool read_fragment_table(struct PkgData *pdata)
{
	int i, indexes = SQUASHFS_FRAGMENT_INDEXES(pdata->sBlk.fragments);
	long long fragment_table_index[indexes];

	TRACE("read_fragment_table: %d fragments, reading %d fragment indexes "
		"from 0x%llx\n", pdata->sBlk.fragments, indexes,
		pdata->sBlk.fragment_table_start);

	if (pdata->sBlk.fragments == 0)
		return true;

	pdata->fragment_table = malloc(pdata->sBlk.fragments *
			sizeof(struct squashfs_fragment_entry));
	if (!pdata->fragment_table) {
		ERROR("Failed to allocate fragment table\n");
		return false;
	}

	if (!read_fs_bytes(pdata->fd, pdata->sBlk.fragment_table_start,
			SQUASHFS_FRAGMENT_INDEX_BYTES(pdata->sBlk.fragments),
			fragment_table_index)) {
		ERROR("Failed to read fragment table index\n");
		return false;
	}

	for (i = 0; i < indexes; i++) {
		int length = read_block(pdata, fragment_table_index[i], NULL,
			((char *) pdata->fragment_table) + (i * SQUASHFS_METADATA_SIZE));
		TRACE("Read fragment table block %d, from 0x%llx, length %d\n",
			i, fragment_table_index[i], length);
		if (length == 0) {
			ERROR("Failed to read fragment table block %d\n", i);
			return false;
		}
	}

	return true;
}

static struct inode *read_inode(struct PkgData *pdata,
			unsigned int start_block, unsigned int offset)
{
	union squashfs_inode_header *header = &pdata->header;
	struct inode *i = &pdata->inode;
	long long start = pdata->sBlk.inode_table_start + start_block;
	int bytes = lookup_entry(pdata->inode_table_hash, start);
	void *block_ptr = pdata->inode_table + bytes + offset;

	TRACE("read_inode: reading inode [%d:%d]\n", start_block,  offset);

	if (bytes == -1) {
		ERROR("Inode table block %lld not found\n", start);
		return NULL;
	}

	memcpy(&header->base, block_ptr, sizeof(*(&header->base)));

	i->mode = lookup_type[header->base.inode_type] | header->base.mode;
	i->type = header->base.inode_type;
	i->time = header->base.mtime;
	i->inode_number = header->base.inode_number;

	switch(header->base.inode_type) {
		case SQUASHFS_DIR_TYPE: {
			struct squashfs_dir_inode_header *inode = &header->dir;

			memcpy(inode, block_ptr, sizeof(*(inode)));

			i->data = inode->file_size;
			i->offset = inode->offset;
			i->start = inode->start_block;
			break;
		}
		case SQUASHFS_LDIR_TYPE: {
			struct squashfs_ldir_inode_header *inode = &header->ldir;

			memcpy(inode, block_ptr, sizeof(*(inode)));

			i->data = inode->file_size;
			i->offset = inode->offset;
			i->start = inode->start_block;
			break;
		}
		case SQUASHFS_REG_TYPE: {
			struct squashfs_reg_inode_header *inode = &header->reg;

			memcpy(inode, block_ptr, sizeof(*(inode)));

			i->data = inode->file_size;
			i->frag_bytes = inode->fragment == SQUASHFS_INVALID_FRAG
				?  0 : inode->file_size % pdata->sBlk.block_size;
			i->fragment = inode->fragment;
			i->offset = inode->offset;
			i->blocks = inode->fragment == SQUASHFS_INVALID_FRAG ?
				(i->data + pdata->sBlk.block_size - 1) >>
				pdata->sBlk.block_log :
				i->data >> pdata->sBlk.block_log;
			i->start = inode->start_block;
			i->block_ptr = block_ptr + sizeof(*inode);
			break;
		}
		case SQUASHFS_LREG_TYPE: {
			struct squashfs_lreg_inode_header *inode = &header->lreg;

			memcpy(inode, block_ptr, sizeof(*(inode)));

			i->data = inode->file_size;
			i->frag_bytes = inode->fragment == SQUASHFS_INVALID_FRAG
				?  0 : inode->file_size % pdata->sBlk.block_size;
			i->fragment = inode->fragment;
			i->offset = inode->offset;
			i->blocks = inode->fragment == SQUASHFS_INVALID_FRAG ?
				(i->data + pdata->sBlk.block_size - 1) >>
				pdata->sBlk.block_log :
				i->data >> pdata->sBlk.block_log;
			i->start = inode->start_block;
			i->block_ptr = block_ptr + sizeof(*inode);
			break;
		}
		default:
			TRACE("read_inode: skipping inode type %d\n", header->base.inode_type);
			return NULL;
	}
	return i;
}

static struct dir *squashfs_opendir(struct PkgData *pdata,
			unsigned int block_start, unsigned int offset, struct inode **i)
{
	struct squashfs_dir_header dirh;
	char buffer[sizeof(struct squashfs_dir_entry) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	struct squashfs_dir_entry *dire = (struct squashfs_dir_entry *) buffer;
	long long start;
	int bytes;
	int dir_count, size;
	struct dir_ent *new_dir;
	struct dir *dir;

	TRACE("squashfs_opendir: inode start block %d, offset %d\n",
		block_start, offset);

	*i = read_inode(pdata, block_start, offset);
	if (!*i) {
		ERROR("Failed to read directory inode\n");
		return NULL;
	}

	start = pdata->sBlk.directory_table_start + (*i)->start;
	bytes = lookup_entry(pdata->directory_table_hash, start);
	if (bytes == -1) {
		ERROR("Failed to open directory: block %d not found\n", block_start);
		return NULL;
	}

	bytes += (*i)->offset;
	size = (*i)->data + bytes - 3;

	dir = malloc(sizeof(struct dir));
	if (!dir) {
		ERROR("Failed to allocate directory struct\n");
		return NULL;
	}

	dir->dir_count = 0;
	dir->cur_entry = 0;
	dir->mode = (*i)->mode;
	dir->mtime = (*i)->time;
	dir->dirs = NULL;

	while(bytes < size) {
		memcpy(&dirh, pdata->directory_table + bytes, sizeof(*(&dirh)));

		dir_count = dirh.count + 1;
		TRACE("squashfs_opendir: Read directory header @ byte position "
			"%d, %d directory entries\n", bytes, dir_count);
		bytes += sizeof(dirh);

		while(dir_count--) {
			memcpy(dire, pdata->directory_table + bytes, sizeof(*(dire)));

			bytes += sizeof(*dire);

			memcpy(dire->name, pdata->directory_table + bytes,
				dire->size + 1);
			dire->name[dire->size + 1] = '\0';
			TRACE("squashfs_opendir: directory entry %s, inode "
				"%d:%d, type %d\n", dire->name,
				dirh.start_block, dire->offset, dire->type);
			if((dir->dir_count % DIR_ENT_SIZE) == 0) {
				new_dir = realloc(dir->dirs, (dir->dir_count +
					DIR_ENT_SIZE) * sizeof(struct dir_ent));
				if (!new_dir) {
					ERROR("Failed to (re)allocate directory contents\n");
					free(dir);
					return NULL;
				}
				dir->dirs = new_dir;
			}
			strcpy(dir->dirs[dir->dir_count].name, dire->name);
			dir->dirs[dir->dir_count].start_block =
				dirh.start_block;
			dir->dirs[dir->dir_count].offset = dire->offset;
			dir->dirs[dir->dir_count].type = dire->type;
			dir->dir_count ++;
			bytes += dire->size + 1;
		}
	}

	return dir;
}

static int squashfs_uncompress(struct PkgData *pdata,
			void *d, void *s, int size, int block_size, int *error)
{
#if USE_GZIP
	if (pdata->sBlk.compression == ZLIB_COMPRESSION) {
		unsigned long bytes_zlib = block_size;
		*error = uncompress(d, &bytes_zlib, s, size);
		return *error == Z_OK ? (int) bytes_zlib : -1;
	}
#endif
#if USE_LZO
	if (pdata->sBlk.compression == LZO_COMPRESSION) {
		lzo_uint bytes_lzo = block_size;
		*error = lzo1x_decompress_safe(s, size, d, &bytes_lzo, NULL);
		return *error == LZO_E_OK ? bytes_lzo : -1;
	}
#endif
	*error = -EINVAL;
	return -1;
}

static bool read_data_block(struct PkgData *pdata, void *buf, int buf_size,
		long long block, int size)
{
	const int csize = SQUASHFS_COMPRESSED_SIZE_BLOCK(size);
	if (SQUASHFS_COMPRESSED_BLOCK(size)) { // compressed block
		if (csize >= buf_size) {
			// In the case compression doesn't make a block smaller,
			// mksquashfs will store the block uncompressed.
			ERROR("Refusing to load too-large compressed block\n");
			return false;
		}

		// Load compressed data into temporary buffer.
		char tmp[csize];
		if (!read_fs_bytes(pdata->fd, block, sizeof(tmp), tmp)) {
			return false;
		}

		int error, res = squashfs_uncompress(
				pdata, buf, tmp, sizeof(tmp), buf_size, &error);
		if (res == -1) {
			ERROR("Uncompress failed with error code %d\n", error);
			return false;
		}

		return true;

	} else { // uncompressed block
		if (csize != buf_size) {
			ERROR("Refusing to load size-mismatched uncompressed block\n");
			return false;
		}

		return read_fs_bytes(pdata->fd, block, buf_size, buf);
	}
}

static bool add_entry(struct hash_table_entry *hash_table[], long long start,
	int bytes)
{
	int hash = CALCULATE_HASH(start);
	struct hash_table_entry *hash_table_entry;

	hash_table_entry = malloc(sizeof(struct hash_table_entry));
	if (!hash_table_entry) {
		ERROR("Failed to allocate hash table entry\n");
		return false;
	}

	hash_table_entry->start = start;
	hash_table_entry->bytes = bytes;
	hash_table_entry->next = hash_table[hash];
	hash_table[hash] = hash_table_entry;

	return true;
}

int lookup_entry(struct hash_table_entry *hash_table[], long long start)
{
	int hash = CALCULATE_HASH(start);
	struct hash_table_entry *hash_table_entry;

	for(hash_table_entry = hash_table[hash]; hash_table_entry;
				hash_table_entry = hash_table_entry->next)

		if(hash_table_entry->start == start)
			return hash_table_entry->bytes;

	return -1;
}

static bool read_fs_bytes(int fd, long long byte, int bytes, void *buff)
{
	off_t off = byte;
	int res, count;

	TRACE("read_bytes: reading from position 0x%llx, bytes %d\n", byte,
		bytes);

	if(lseek(fd, off, SEEK_SET) == -1) {
		ERROR("Lseek failed because %s\n", strerror(errno));
		return false;
	}

	for(count = 0; count < bytes; count += res) {
		res = read(fd, buff + count, bytes - count);
		if(res < 1) {
			if(res == 0) {
				ERROR("Read on filesystem failed because "
					"EOF\n");
				return false;
			} else if(errno != EINTR) {
				ERROR("Read on filesystem failed because %s\n",
						strerror(errno));
				return false;
			} else
				res = 0;
		}
	}

	return true;
}

static int read_block(struct PkgData *pdata,
			long long start, long long *next, void *block)
{
	unsigned short c_byte;
	int offset = 2;
	int fd = pdata->fd;

	if (!read_fs_bytes(fd, start, 2, &c_byte)) {
		goto failed;
	}

	TRACE("read_block: block @0x%llx, %d %s bytes\n", start,
		SQUASHFS_COMPRESSED_SIZE(c_byte), SQUASHFS_COMPRESSED(c_byte) ?
		"compressed" : "uncompressed");

	if(SQUASHFS_COMPRESSED(c_byte)) {
		char buffer[SQUASHFS_METADATA_SIZE];
		int error, res;

		c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte);
		if (!read_fs_bytes(fd, start + offset, c_byte, buffer)) {
			goto failed;
		}

		res = squashfs_uncompress(pdata, block, buffer, c_byte,
			SQUASHFS_METADATA_SIZE, &error);

		if(res == -1) {
			ERROR("uncompress failed with error code %d\n", error);
			goto failed;
		}
		if(next)
			*next = start + offset + c_byte;
		return res;
	} else {
		c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte);
		if (!read_fs_bytes(fd, start + offset, c_byte, block)) {
			goto failed;
		}
		if(next)
			*next = start + offset + c_byte;
		return c_byte;
	}

failed:
	ERROR("read_block: failed to read block @0x%llx\n", start);
	return 0;
}

static bool uncompress_inode_table(struct PkgData *pdata)
{
	int size = 0, bytes = 0, res;
	long long start = pdata->sBlk.inode_table_start;
	long long end = pdata->sBlk.directory_table_start;

	TRACE("uncompress_inode_table: start %lld, end %lld\n", start, end);
	while(start < end) {
		if(size - bytes < SQUASHFS_METADATA_SIZE) {
			pdata->inode_table = realloc(pdata->inode_table,
						size += SQUASHFS_METADATA_SIZE);
			if (!pdata->inode_table) {
				ERROR("Failed to (re)allocate inode table\n");
				return false;
			}
		}
		TRACE("uncompress_inode_table: reading block 0x%llx\n", start);
		if (!add_entry(pdata->inode_table_hash, start, bytes)) {
			return false;
		}
		res = read_block(pdata, start, &start, pdata->inode_table + bytes);
		if (res == 0) {
			ERROR("Failed to read inode table block\n");
			return false;
		}
		bytes += res;
	}

	return true;
}

static bool write_buf(struct PkgData *pdata, struct inode *inode, char *buf)
{
	TRACE("write_buf: regular file, blocks %d\n", inode->blocks);

	const int file_end = inode->data / pdata->sBlk.block_size;
	long long start = inode->start;
	for (int i = 0; i < inode->blocks; i++) {
		unsigned int csize = inode->block_ptr[i];
		int size =
			  i == file_end
			? inode->data & (pdata->sBlk.block_size - 1)
			: pdata->sBlk.block_size;

		if (csize == 0) { // sparse file
			memset(buf, 0, size);
		} else {
			if (!read_data_block(pdata, buf, size, start, csize)) {
				return false;
			}
			start += SQUASHFS_COMPRESSED_SIZE_BLOCK(csize);
		}
		buf += size;
	}

	if (inode->frag_bytes) {
		TRACE("read_fragment: reading fragment %d\n", inode->fragment);

		struct squashfs_fragment_entry *fragment_entry =
				&pdata->fragment_table[inode->fragment];

		void *data = malloc(pdata->sBlk.block_size);
		if (!data) {
			ERROR("Failed to allocate block data buffer\n");
			return false;
		}

		if (!read_data_block(pdata, data, pdata->sBlk.block_size,
				fragment_entry->start_block, fragment_entry->size)) {
			free(data);
			return false;
		}

		memcpy(buf, data + inode->offset, inode->frag_bytes);
		free(data);
	}

	return true;
}

static bool uncompress_directory_table(struct PkgData *pdata)
{
	int bytes = 0, size = 0, res;
	long long start = pdata->sBlk.directory_table_start;
	long long end = pdata->sBlk.fragment_table_start;

	TRACE("uncompress_directory_table: start %lld, end %lld\n", start, end);

	while(start < end) {
		if(size - bytes < SQUASHFS_METADATA_SIZE) {
			pdata->directory_table = realloc(pdata->directory_table,
						size += SQUASHFS_METADATA_SIZE);
			if (!pdata->directory_table) {
				ERROR("Failed to (re)allocate directory table\n");
				return false;
			}
		}
		TRACE("uncompress_directory_table: reading block 0x%llx\n",
				start);
		if (!add_entry(pdata->directory_table_hash, start, bytes)) {
			return false;
		}
		res = read_block(pdata, start, &start, pdata->directory_table + bytes);
		if (res == 0) {
			ERROR("Failed to read directory table block\n");
			return false;
		}
		bytes += res;
	}

	return true;
}

static bool squashfs_readdir(struct dir *dir, char **name,
			unsigned int *start_block, unsigned int *offset, unsigned int *type)
{
	if (dir->cur_entry == dir->dir_count) {
		return false;
	}

	*name = dir->dirs[dir->cur_entry].name;
	*start_block = dir->dirs[dir->cur_entry].start_block;
	*offset = dir->dirs[dir->cur_entry].offset;
	*type = dir->dirs[dir->cur_entry].type;
	dir->cur_entry ++;

	return true;
}

static void squashfs_closedir(struct dir *dir)
{
	free(dir->dirs);
	free(dir);
}

static bool read_super(struct PkgData *pdata, const char *source)
{
	/*
	 * Try to read a Squashfs 4 superblock
	 */
	if (!read_fs_bytes(pdata->fd, SQUASHFS_START,
			sizeof(struct squashfs_super_block), &pdata->sBlk)) {
		ERROR("Failed to read SQUASHFS superblock on %s\n", source);
		return false;
	}

	if(pdata->sBlk.s_magic == SQUASHFS_MAGIC && pdata->sBlk.s_major == 4 &&
			pdata->sBlk.s_minor == 0) {
		return true;
	} else {
		ERROR("Invalid SQUASHFS superblock on %s\n", source);
		return false;
	}
}

// TODO: There is currently no way to tell apart "no such file" from other
//       errors such as allocation failures.
static struct inode *get_inode_from_dir(struct PkgData *pdata,
			const char *name, unsigned int start_block, unsigned int offset)
{
	char *n;
	struct inode *i;
	unsigned int type;
	struct dir *dir;

	dir = squashfs_opendir(pdata, start_block, offset, &i);
	if (!dir) {
		return NULL;
	}

	i = NULL;
	while(squashfs_readdir(dir, &n, &start_block, &offset, &type)) {
		if(type == SQUASHFS_DIR_TYPE)
			i = get_inode_from_dir(pdata, name, start_block, offset);

		else if (!strcmp(n, name))
			i = read_inode(pdata, start_block, offset);

		if (i)
			break;
	}

	squashfs_closedir(dir);
	return i;
}

static struct inode *get_inode(struct PkgData *pdata, const char *name)
{
	return get_inode_from_dir(pdata, name,
				SQUASHFS_INODE_BLK(pdata->sBlk.root_inode),
				SQUASHFS_INODE_OFFSET(pdata->sBlk.root_inode));
}

const char *opk_sqfs_get_metadata(struct PkgData *pdata)
{
	struct inode *i;
	unsigned int start_block = SQUASHFS_INODE_BLK(pdata->sBlk.root_inode);
	unsigned int offset = SQUASHFS_INODE_OFFSET(pdata->sBlk.root_inode);
	unsigned int type;
	char *n, *ptr;

	if (!pdata->dir) {
		pdata->dir = squashfs_opendir(pdata, start_block, offset, &i);
		if (!pdata->dir) {
			return NULL;
		}
	}

	while(squashfs_readdir(pdata->dir, &n, &start_block, &offset, &type)) {
		if (type != SQUASHFS_REG_TYPE && type != SQUASHFS_LREG_TYPE)
			continue;

		ptr = strrchr(n, '.');
		if (ptr && !strcmp(ptr + 1, "desktop"))
			return n;
	}

	squashfs_closedir(pdata->dir);
	pdata->dir = NULL;
	return NULL;
}

struct PkgData *opk_sqfs_open(const char *image_name)
{
	struct PkgData *pdata;

	pdata = calloc(1, sizeof(*pdata));
	if (!pdata) {
		ERROR("Unable to create data structure: %s\n", strerror(errno));
		goto fail_exit;
	}

	if ((pdata->fd = open(image_name, O_RDONLY)) == -1) {
		ERROR("Could not open %s: %s\n", image_name, strerror(errno));
		goto fail_free;
	}

	if (!read_super(pdata, image_name)) {
		ERROR("Could not read superblock\n");
		goto fail_close;
	}

	if (!read_fragment_table(pdata)) {
		ERROR("Failed to read fragment table\n");
		goto fail_close;
	}

	if (!uncompress_inode_table(pdata)) {
		goto fail_close;
	}
	if (!uncompress_directory_table(pdata)) {
		goto fail_close;
	}

	return pdata;

fail_close:
	close(pdata->fd);
fail_free:
	free(pdata->inode_table);
	free(pdata->directory_table);
	free(pdata->fragment_table);
	free(pdata);
fail_exit:
	return NULL;
}

void opk_sqfs_close(struct PkgData *pdata)
{
	if (pdata->dir)
		squashfs_closedir(pdata->dir);

	close(pdata->fd);

	free(pdata->inode_table);
	free(pdata->directory_table);
	free(pdata->fragment_table);
	free(pdata);
}

char *opk_sqfs_extract_file(struct PkgData *pdata, const char *name)
{
	struct inode *i;
	char *buf;

	i = get_inode(pdata, name);
	if (!i) {
		ERROR("Unable to find inode for path \"%s\"\n", name);
		return NULL;
	}

	buf = calloc(1, i->data + 1);
	if (!buf) {
		ERROR("Unable to allocate file extraction buffer\n");
		return NULL;
	}

	if (!write_buf(pdata, i, buf)) {
		free(buf);
		return NULL;
	}

	return buf;
}
