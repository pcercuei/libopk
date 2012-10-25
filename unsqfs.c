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

#define _GNU_SOURCE

#define TRUE 1
#define FALSE 0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <zlib.h>
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>

#define SQUASHFS_CACHED_FRAGMENTS	CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE	
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
#define SQUASHFS_FILE_TYPE		2
#define SQUASHFS_LDIR_TYPE		8

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

#define EXIT_UNSQUASH(s, args...) \
		do { \
			fprintf(stderr, "FATAL ERROR aborting: "s, ## args); \
			exit(1); \
		} while(0)

#define CALCULATE_HASH(start)	(start & 0xffff)

struct hash_table_entry {
	long long	start;
	int		bytes;
	struct hash_table_entry *next;
};

struct inode {
	int blocks;
	char *block_ptr;
	long long data;
	int fragment;
	int frag_bytes;
	int inode_number;
	int mode;
	int offset;
	long long start;
	time_t time;
	int type;
	char sparse;
};

/* Cache status struct */
struct cache {
	int	buffer_size;
	struct cache_entry *hash_table[65536];
};

/* struct describing a cache entry */
struct cache_entry {
	struct cache *cache;
	long long block;
	int	size;
	char *data;
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

struct file_entry {
	int offset;
	int size;
	struct cache_entry *buffer;
};

struct squashfs_file {
	int fd;
	int blocks;
	long long file_size;
	int mode;
	time_t time;
	char *pathname;
	char sparse;
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

	struct squashfs_file *file;
	long long hole;

	struct squashfs_fragment_entry *fragment_table;
	struct cache *fragment_cache, *data_cache;
	struct hash_table_entry *inode_table_hash[65536],
							*directory_table_hash[65536];

	int fd, bytes, file_count, dir_count;
	char *inode_table, *directory_table,
		 *zero_data;
	unsigned int block_log, cur_blocks;

	/* buffer to return to caller*/
	char *private_buffer;
	int private_count;
	off_t offset;
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
static int read_fs_bytes(int fd, long long byte, int bytes, void *buff);
static int read_block(struct PkgData *pdata,
			long long start, long long *next, void *block);
static int lookup_entry(struct hash_table_entry *hash_table[], long long start);
static void *reader(struct PkgData *pdata, struct cache_entry *entry);
static void *writer(struct PkgData *pdata, void *arg);
static void *deflator(struct PkgData *pdata, struct cache_entry *entry);


static void read_block_list(unsigned int *block_list, char *block_ptr, int blocks)
{
	TRACE("read_block_list: blocks %d\n", blocks);

	memcpy(block_list, block_ptr, blocks * sizeof(unsigned int));
}

static int read_fragment_table(struct PkgData *pdata)
{
	int res, i, indexes = SQUASHFS_FRAGMENT_INDEXES(pdata->sBlk.fragments);
	long long fragment_table_index[indexes];

	TRACE("read_fragment_table: %d fragments, reading %d fragment indexes "
		"from 0x%llx\n", pdata->sBlk.fragments, indexes,
		pdata->sBlk.fragment_table_start);

	if(pdata->sBlk.fragments == 0)
		return TRUE;

	pdata->fragment_table = malloc(pdata->sBlk.fragments *
		sizeof(struct squashfs_fragment_entry));
	if(pdata->fragment_table == NULL)
		EXIT_UNSQUASH("read_fragment_table: failed to allocate "
			"fragment table\n");

	res = read_fs_bytes(pdata->fd, pdata->sBlk.fragment_table_start,
		SQUASHFS_FRAGMENT_INDEX_BYTES(pdata->sBlk.fragments),
		fragment_table_index);
	if(res == FALSE) {
		ERROR("read_fragment_table: failed to read fragment table "
			"index\n");
		return FALSE;
	}

	for(i = 0; i < indexes; i++) {
		int length = read_block(pdata, fragment_table_index[i], NULL,
			((char *) pdata->fragment_table) + (i *
			SQUASHFS_METADATA_SIZE));
		TRACE("Read fragment table block %d, from 0x%llx, length %d\n",
			i, fragment_table_index[i], length);
		if(length == FALSE) {
			ERROR("read_fragment_table: failed to read fragment "
				"table index\n");
			return FALSE;
		}
	}

	return TRUE;
}

static void read_fragment(struct PkgData *pdata,
			unsigned int fragment, long long *start_block, int *size)
{
	TRACE("read_fragment: reading fragment %d\n", fragment);

	struct squashfs_fragment_entry *fragment_entry;

	fragment_entry = &pdata->fragment_table[fragment];
	*start_block = fragment_entry->start_block;
	*size = fragment_entry->size;
}

static struct inode *read_inode(struct PkgData *pdata,
			unsigned int start_block, unsigned int offset)
{
	union squashfs_inode_header *header = &pdata->header;
	struct inode *i = &pdata->inode;
	long long start = pdata->sBlk.inode_table_start + start_block;
	int bytes = lookup_entry(pdata->inode_table_hash, start);
	char *block_ptr = pdata->inode_table + bytes + offset;

	TRACE("read_inode: reading inode [%d:%d]\n", start_block,  offset);

	if(bytes == -1)
		EXIT_UNSQUASH("read_inode: inode table block %lld not found\n",
			start); 		

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
		case SQUASHFS_FILE_TYPE: {
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
			i->sparse = 0;
			i->block_ptr = block_ptr + sizeof(*inode);
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
	start = pdata->sBlk.directory_table_start + (*i)->start;
	bytes = lookup_entry(pdata->directory_table_hash, start);

	if(bytes == -1)
		EXIT_UNSQUASH("squashfs_opendir: directory block %d not "
			"found!\n", block_start);

	bytes += (*i)->offset;
	size = (*i)->data + bytes - 3;

	dir = malloc(sizeof(struct dir));
	if(dir == NULL)
		EXIT_UNSQUASH("squashfs_opendir: malloc failed!\n");

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
				if(new_dir == NULL)
					EXIT_UNSQUASH("squashfs_opendir: "
						"realloc failed!\n");
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
	unsigned long bytes_zlib;
	lzo_uint bytes_lzo;

	if (pdata->sBlk.compression == ZLIB_COMPRESSION) {
		bytes_zlib = block_size;
		*error = uncompress(d, &bytes_zlib, s, size);
		return *error == Z_OK ? (int) bytes_zlib : -1;
	} else {
		bytes_lzo = block_size;
		*error = lzo1x_decompress_safe(s, size, d, &bytes_lzo, NULL);
		return *error == LZO_E_OK ? bytes_lzo : -1;
	}
}

static struct cache *cache_init(int buffer_size)
{
	struct cache *cache = malloc(sizeof(struct cache));

	if(cache == NULL)
		EXIT_UNSQUASH("Out of memory in cache_init\n");

	cache->buffer_size = buffer_size;
	memset(cache->hash_table, 0, sizeof(struct cache_entry *) * 65536);

	return cache;
}

static struct cache_entry *cache_get(struct PkgData *pdata,
			struct cache *cache, long long block, int size)
{
	/*
	 * Get a block out of the cache.  If the block isn't in the cache
 	 * it is added and queued to the reader() and deflate() threads for
 	 * reading off disk and decompression.  The cache grows until max_blocks
 	 * is reached, once this occurs existing discarded blocks on the free
 	 * list are reused
 	 */
	struct cache_entry *entry;

	entry = malloc(sizeof(struct cache_entry));
	if(entry == NULL)
		EXIT_UNSQUASH("Out of memory in cache_get\n");
	entry->data = malloc(cache->buffer_size);
	if(entry->data == NULL)
		EXIT_UNSQUASH("Out of memory in cache_get\n");

	entry->cache = cache;
	entry->block = block;
	entry->size = size;

	return reader(pdata, entry);
}
	
static void add_entry(struct hash_table_entry *hash_table[], long long start,
	int bytes)
{
	int hash = CALCULATE_HASH(start);
	struct hash_table_entry *hash_table_entry;

	hash_table_entry = malloc(sizeof(struct hash_table_entry));
	if(hash_table_entry == NULL)
		EXIT_UNSQUASH("Out of memory in add_entry\n");

	hash_table_entry->start = start;
	hash_table_entry->bytes = bytes;
	hash_table_entry->next = hash_table[hash];
	hash_table[hash] = hash_table_entry;
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

static int read_fs_bytes(int fd, long long byte, int bytes, void *buff)
{
	off_t off = byte;
	int res, count;

	TRACE("read_bytes: reading from position 0x%llx, bytes %d\n", byte,
		bytes);

	if(lseek(fd, off, SEEK_SET) == -1) {
		ERROR("Lseek failed because %s\n", strerror(errno));
		return FALSE;
	}

	for(count = 0; count < bytes; count += res) {
		res = read(fd, buff + count, bytes - count);
		if(res < 1) {
			if(res == 0) {
				ERROR("Read on filesystem failed because "
					"EOF\n");
				return FALSE;
			} else if(errno != EINTR) {
				ERROR("Read on filesystem failed because %s\n",
						strerror(errno));
				return FALSE;
			} else
				res = 0;
		}
	}

	return TRUE;
}

static int read_block(struct PkgData *pdata,
			long long start, long long *next, void *block)
{
	unsigned short c_byte;
	int offset = 2;
	int fd = pdata->fd;
	
	if(read_fs_bytes(fd, start, 2, &c_byte) == FALSE)
		goto failed;

	TRACE("read_block: block @0x%llx, %d %s bytes\n", start,
		SQUASHFS_COMPRESSED_SIZE(c_byte), SQUASHFS_COMPRESSED(c_byte) ?
		"compressed" : "uncompressed");

	if(SQUASHFS_COMPRESSED(c_byte)) {
		char buffer[SQUASHFS_METADATA_SIZE];
		int error, res;

		c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte);
		if(read_fs_bytes(fd, start + offset, c_byte, buffer) == FALSE)
			goto failed;

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
		if(read_fs_bytes(fd, start + offset, c_byte, block) == FALSE)
			goto failed;
		if(next)
			*next = start + offset + c_byte;
		return c_byte;
	}

failed:
	ERROR("read_block: failed to read block @0x%llx\n", start);
	return FALSE;
}

static void uncompress_inode_table(struct PkgData *pdata)
{
	int size = 0, bytes = 0, res;
	long long start = pdata->sBlk.inode_table_start;
	long long end = pdata->sBlk.directory_table_start;

	TRACE("uncompress_inode_table: start %lld, end %lld\n", start, end);
	while(start < end) {
		if(size - bytes < SQUASHFS_METADATA_SIZE) {
			pdata->inode_table = realloc(pdata->inode_table,
						size += SQUASHFS_METADATA_SIZE);
			if(pdata->inode_table == NULL)
				EXIT_UNSQUASH("Out of memory in "
					"uncompress_inode_table");
		}
		TRACE("uncompress_inode_table: reading block 0x%llx\n", start);
		add_entry(pdata->inode_table_hash, start, bytes);
		res = read_block(pdata, start, &start, pdata->inode_table + bytes);
		if(res == 0) {
			free(pdata->inode_table);
			EXIT_UNSQUASH("uncompress_inode_table: failed to read "
				"block \n");
		}
		bytes += res;
	}
}

static int write_bytes(struct PkgData *pdata, int fd, char *buff, int bytes)
{
	memcpy(pdata->private_buffer + pdata->offset, buff, bytes);
	pdata->offset += bytes;
	return 0;
}

static int write_block(struct PkgData *pdata, int file_fd,
			char *buffer, int size, long long hole, int sparse)
{
	unsigned int block_size = pdata->sBlk.block_size;

	if(hole) {
		if(sparse == FALSE && pdata->zero_data == NULL) {
			if((pdata->zero_data = malloc(block_size)) == NULL)
				EXIT_UNSQUASH("write_block: failed to alloc "
					"zero data block\n");
			memset(pdata->zero_data, 0, block_size);
		}

		if(sparse == FALSE) {
			int blocks = (hole + block_size -1) / block_size;
			int avail_bytes, i;
			for(i = 0; i < blocks; i++, hole -= avail_bytes) {
				avail_bytes = hole > block_size ? block_size :
					hole;
				if(write_bytes(pdata, file_fd, pdata->zero_data, avail_bytes)
						== -1)
					goto failure;
			}
		}
	}

	if(write_bytes(pdata, file_fd, buffer, size) == -1)
		goto failure;

	return TRUE;

failure:
	return FALSE;
}

static int write_file(struct PkgData *pdata,
			struct inode *inode, char *pathname)
{
	unsigned int file_fd, i;
	unsigned int *block_list;
	int file_end = inode->data / pdata->sBlk.block_size;
	long long start = inode->start;
	struct squashfs_file *file;

	TRACE("write_file: regular file, blocks %d\n", inode->blocks);

	file_fd = 0;

	block_list = malloc(inode->blocks * sizeof(unsigned int));
	if(block_list == NULL)
		EXIT_UNSQUASH("write_file: unable to malloc block list\n");

	read_block_list(block_list, inode->block_ptr, inode->blocks);

	file = malloc(sizeof(struct squashfs_file));
	if(file == NULL)
		EXIT_UNSQUASH("write_file: unable to malloc file\n");

	/*
	 * the writer thread is queued a squashfs_file structure describing the
 	 * file.  If the file has one or more blocks or a fragments they are
 	 * queued separately (references to blocks in the cache).
 	 */
	file->fd = file_fd;
	file->file_size = inode->data;
	file->mode = inode->mode;
	file->time = inode->time;
	file->pathname = strdup(pathname);
	file->blocks = inode->blocks + (inode->frag_bytes > 0);
	file->sparse = inode->sparse;
	writer(pdata, file);

	for(i = 0; i < inode->blocks; i++) {
		int c_byte = SQUASHFS_COMPRESSED_SIZE_BLOCK(block_list[i]);
		struct file_entry *block = malloc(sizeof(struct file_entry));

		if(block == NULL)
			EXIT_UNSQUASH("write_file: unable to malloc file\n");
		block->offset = 0;
		block->size = i == file_end ?
		  inode->data & (pdata->sBlk.block_size - 1) : pdata->sBlk.block_size;
		if(block_list[i] == 0) /* sparse file */
			block->buffer = NULL;
		else {
			block->buffer = cache_get(pdata, pdata->data_cache,
						start, block_list[i]);
			start += c_byte;
		}
		writer(pdata, block);
	}

	if(inode->frag_bytes) {
		int size;
		long long start;
		struct file_entry *block = malloc(sizeof(struct file_entry));

		if(block == NULL)
			EXIT_UNSQUASH("write_file: unable to malloc file\n");
		read_fragment(pdata, inode->fragment, &start, &size);
		block->buffer = cache_get(pdata, pdata->fragment_cache, start, size);
		block->offset = inode->offset;
		block->size = inode->frag_bytes;
		writer(pdata, block);
	}

	free(block_list);
	return TRUE;
}

static void uncompress_directory_table(struct PkgData *pdata)
{
	int bytes = 0, size = 0, res;
	long long start = pdata->sBlk.directory_table_start;
	long long end = pdata->sBlk.fragment_table_start;

	TRACE("uncompress_directory_table: start %lld, end %lld\n", start, end);

	while(start < end) {
		if(size - bytes < SQUASHFS_METADATA_SIZE) {
			pdata->directory_table = realloc(pdata->directory_table,
						size += SQUASHFS_METADATA_SIZE);
			if(pdata->directory_table == NULL)
				EXIT_UNSQUASH("Out of memory in "
					"uncompress_directory_table\n");
		}
		TRACE("uncompress_directory_table: reading block 0x%llx\n",
				start);
		add_entry(pdata->directory_table_hash, start, bytes);
		res = read_block(pdata, start, &start, pdata->directory_table + bytes);
		if(res == 0)
			EXIT_UNSQUASH("uncompress_directory_table: failed to "
				"read block\n");
		bytes += res;
	}
}

static int squashfs_readdir(struct dir *dir, char **name,
			unsigned int *start_block, unsigned int *offset, unsigned int *type)
{
	if(dir->cur_entry == dir->dir_count)
		return FALSE;

	*name = dir->dirs[dir->cur_entry].name;
	*start_block = dir->dirs[dir->cur_entry].start_block;
	*offset = dir->dirs[dir->cur_entry].offset;
	*type = dir->dirs[dir->cur_entry].type;
	dir->cur_entry ++;

	return TRUE;
}

static void squashfs_closedir(struct dir *dir)
{
	free(dir->dirs);
	free(dir);
}

static int read_super(struct PkgData *pdata, const char *source)
{
	/*
	 * Try to read a Squashfs 4 superblock
	 */
	read_fs_bytes(pdata->fd, SQUASHFS_START, sizeof(struct squashfs_super_block),
		&pdata->sBlk);

	if(pdata->sBlk.s_magic == SQUASHFS_MAGIC && pdata->sBlk.s_major == 4 &&
			pdata->sBlk.s_minor == 0) {
		return TRUE;
	} else {
		ERROR("Can't find a SQUASHFS superblock on %s\n", source);
		return FALSE;
	}
}

static struct inode *get_inode_from_dir(struct PkgData *pdata,
			const char *name, unsigned int start_block, unsigned int offset)
{
	char *n;
	struct inode *i;
	unsigned int type;
	struct dir *dir = squashfs_opendir(pdata, start_block, offset, &i);
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

/*
 * reader thread.  This thread processes read requests queued by the
 * cache_get() routine.
 */
static void *reader(struct PkgData *pdata, struct cache_entry *entry)
{
	int res = read_fs_bytes(pdata->fd, entry->block,
		SQUASHFS_COMPRESSED_SIZE_BLOCK(entry->size),
		entry->data);

	if(res && SQUASHFS_COMPRESSED_BLOCK(entry->size))
		/*
		 * queue successfully read block to the deflate
		 * thread(s) for further processing
 		 */
		deflator(pdata, entry);

	return entry;
}

/*
 * writer thread.  This processes file write requests queued by the
 * write_file() routine.
 */
static void *writer(struct PkgData *pdata, void *arg)
{
	struct squashfs_file *file = pdata->file;
	long long hole = pdata->hole;
	struct file_entry *block;

	if (file == NULL) {
		pdata->file = (struct squashfs_file *)arg;
		return pdata->file;
	}

	TRACE("writer: regular file, blocks %d\n", file->blocks);

	block = (struct file_entry *)arg;

	if(block->buffer == 0) { /* sparse file */
		hole += block->size;
	} else {
		write_block(pdata, file->fd, block->buffer->data +
			block->offset, block->size, hole, file->sparse);
	}
	free(block);

	if (++pdata->cur_blocks == file->blocks) {
		close(file->fd);
		free(file->pathname);
		pdata->cur_blocks = 0;
		hole = 0;
		free(file);
		file = NULL;
	}
	return NULL;
}

/*
 * decompress thread.  This decompresses buffers queued by the read thread
 */
static void *deflator(struct PkgData *pdata, struct cache_entry *entry)
{
	char tmp[pdata->sBlk.block_size];
	int error, res;

		res = squashfs_uncompress(pdata, tmp, entry->data,
			SQUASHFS_COMPRESSED_SIZE_BLOCK(entry->size),
			pdata->sBlk.block_size, &error);

		if(res == -1)
			ERROR("uncompress failed with error code %d\n", error);
		else
			memcpy(entry->data, tmp, res);

		return entry;
}

char *opk_extract_file(const char *image_name, const char *file_name)
{
	struct PkgData *pdata;
	struct inode *i;
	char *buf;

	pdata = calloc(1, sizeof(*pdata));
	if (!pdata)
		EXIT_UNSQUASH("Unable to create data structure: %s\n",
					strerror(errno));

	if((pdata->fd = open(image_name, O_RDONLY)) == -1)
		EXIT_UNSQUASH("Could not open %s, because %s\n", image_name,
			strerror(errno));

	if(read_super(pdata, image_name) == FALSE)
		EXIT_UNSQUASH("Could not read superblock\n");

	if ((pdata->sBlk.compression != ZLIB_COMPRESSION)
				&& (pdata->sBlk.compression != LZO_COMPRESSION))
		EXIT_UNSQUASH("No decompressors available:\n");

	pdata->block_log = pdata->sBlk.block_log;

	pdata->fragment_cache = cache_init(pdata->sBlk.block_size);
	pdata->data_cache = cache_init(pdata->sBlk.block_size);

	if(read_fragment_table(pdata) == FALSE)
		EXIT_UNSQUASH("failed to read fragment table\n");

	uncompress_inode_table(pdata);
	uncompress_directory_table(pdata);

	i = get_inode(pdata, file_name);
	if (!i)
		EXIT_UNSQUASH("Unable to find inode\n");

	pdata->private_buffer = calloc(1, i->data);
	if(pdata->private_buffer == NULL)
		EXIT_UNSQUASH("Unable to allocate private buffer");

	write_file(pdata, i, "");

	buf = pdata->private_buffer;
	free(pdata);
	return buf;
}
