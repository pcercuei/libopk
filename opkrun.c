#define _BSD_SOURCE 1
#include <getopt.h>
#include <limits.h>
#include <opk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MY_NAME
#define MY_NAME "opkrun"
#endif

#ifndef VTCON_FILE
#define VTCON_FILE "/sys/devices/virtual/vtconsole/vtcon1/bind"
#endif

struct params {
	char *exec, *mountpoint;
	char terminal:1,
		 daemon:1,
		 needs_file:1,
		 can_files:1,
		 needs_url:1,
		 can_urls:1;
};


static const struct option options[] = {
	  {"help", no_argument, 0, 'h'},
	  {"metadata", required_argument, 0, 'm'},
	  {0, 0, 0, 0},
};

static const char *options_descriptions[] = {
	"Show this help and quit.",
	"Metadata file to use (default: first one found)",
};


static void usage(void)
{
	printf("Usage:\n\t" MY_NAME " [OPTIONS] OPK_FILE [ARGS ...]\n\nOptions:\n");

	for (size_t i = 0; options[i].name; i++)
		printf("\t-%c, --%s\n\t\t\t%s\n",
					options[i].val, options[i].name,
					options_descriptions[i]);
}

static struct OPK * open_opk(const char *filename, const char *metadata)
{
	struct OPK *opk = opk_open(filename);
	if (!opk) {
		fprintf(stderr, "Unable to open OPK\n");
		return NULL;
	}

	for (;;) {
		const char *meta_file;
		int ret = opk_open_metadata(opk, &meta_file);
		if (ret < 0) {
			fprintf(stderr, "Unable to open metadata file within OPK\n");
			goto close_opk;
		}

		if (!ret) {
			fprintf(stderr, "Metadata file not found in OPK\n");
			goto close_opk;
		}

		if (!metadata || !strcmp(metadata, meta_file))
			break;
	}

	return opk;

close_opk:
	opk_close(opk);
	return NULL;
}

static int read_params(struct OPK *opk, struct params *params)
{
	memset(params, 0, sizeof(*params));
	const char *exec_name = NULL, *name = NULL;
	size_t exec_name_len = 0, name_len = 0;

	for (;;) {
		const char *key, *val;
		size_t skey, sval;
		int ret = opk_read_pair(opk, &key, &skey, &val, &sval);
		if (ret < 0) {
			fprintf(stderr, "Unable to read key/value pair from metadata\n");
			return ret;
		}

		if (!ret)
			break;

		if (!strncmp(key, "Name", skey)) {
			name_len = sval;
			name = val;
		}

		if (!strncmp(key, "Exec", skey)) {
			exec_name_len = sval;
			exec_name = val;
			continue;
		}

		if (!strncmp(key, "Terminal", skey)
					&& !strncmp(val, "true", sval)) {
			params->terminal = 1;
			continue;
		}

		if (!strncmp(key, "X-OD-Daemon", skey)
					&& !strncmp(val, "true", sval))
			params->daemon = 1;
	}

	if (!exec_name || !name) {
		fprintf(stderr, "Unable to find the executable name\n");
		return -1;
	}

	unsigned int i;
	for (i = 0; i < exec_name_len - 1; i++) {
		if (exec_name[i] != '%')
			continue;
		i++;
		if (exec_name[i] == 'f') {
			params->needs_file = 1;
			params->can_files = 1;
		} else if (exec_name[i] == 'F') {
			params->can_files = 1;
		} else if (exec_name[i] == 'u') {
			params->needs_url = 1;
			params->can_urls = 1;
		} else if (exec_name[i] == 'U') {
			params->can_urls = 1;
		} else
			fprintf(stderr,
						"Unhandled token %%%c in Exec line\n", exec_name[i]);
		break;
	}

	for (i = 0; i < exec_name_len; i++)
		if (exec_name[i] == ' ')
			break;

	params->exec = malloc(i + 1);
	memcpy(params->exec, exec_name, i);
	params->exec[i] = '\0';

	params->mountpoint = malloc(name_len + 6);
	sprintf(params->mountpoint, "/mnt/%.*s", (int) name_len, name);
	return 0;
}

static void enable_vtcon(void)
{
	FILE *f = fopen(VTCON_FILE, "w");
	if (!f) {
		perror("Unable to open vtcon file");
		return;
	}

	char one = '1';
	fwrite(&one, 1, 1, f);
	fclose(f);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Error: Too few arguments given.\n\n");
		usage();
		return EXIT_SUCCESS;
	}

	int c, option_index = 0, arg_index = 1;
	const char *metadata = NULL;

	while ((c = getopt_long(argc, argv, "hm:",
						options, &option_index)) != -1) {
		switch (c) {
			case 'h':
				usage();
				return EXIT_SUCCESS;

			case 'm':
				metadata = optarg;
				arg_index += 2;
				break;

			case '?':
				return EXIT_FAILURE;
		}
	}

	const char *opk_name = argv[arg_index];
	struct OPK *opk = open_opk(opk_name, metadata);
	if (!opk)
		return EXIT_FAILURE;

	struct params params;
	int ret = read_params(opk, &params);
	opk_close(opk);
	if (ret < 0)
		return EXIT_FAILURE;

	char *args[16] = {
		params.exec, NULL,
	};

	char **opk_argv = argv + arg_index + 1;
	int opk_argc = argc - arg_index - 1;
	if (opk_argc > 14)
		opk_argc = 14;

	if (!opk_argc && (params.needs_file || params.needs_url))
		fprintf(stderr, "WARNING: OPK requires a parameter, but none was given\n");

	if (params.can_files) {
		int i;
		for (i = 0; i < opk_argc; i++)
			args[i + 1] = realpath(opk_argv[i], NULL);
		args[i] = NULL;
	} else if (params.can_urls) {
		int i;
		for (i = 0; i < opk_argc; i++) {
			char *url = realpath(opk_argv[i], NULL);
			if (url) {
				char *tmp = malloc(strlen(url) + sizeof "file://");
				sprintf(tmp, "file://%s", url);
				free(url);
				url = tmp;
			}
			args[i + 1] = url;
		}
		args[i] = NULL;
	}

	umount(params.mountpoint);
	mkdir(params.mountpoint, 0755);

	char buf[256];
	sprintf(buf, "mount -o loop,nodev,nosuid,ro %s %s >/dev/null 2>&1",
				opk_name, params.mountpoint);
	ret = system(buf);
	if (ret < 0) {
		perror("Unable to mount OPK");
		free(params.exec);
		free(params.mountpoint);
		return EXIT_FAILURE;
	}

	chdir(params.mountpoint);

	if (params.terminal)
		enable_vtcon();

	pid_t son = fork();
	if (!son) {
		sprintf(buf, "%s/%s", params.mountpoint, params.exec);
		if (!access(buf, X_OK))
			execv(buf, args);
		execvp(params.exec, args);
	}

	if (params.daemon && fork())
		return EXIT_SUCCESS;

	int status;
	waitpid(son, &status, 0);

	chdir("/");
	umount(params.mountpoint);
	rmdir(params.mountpoint);
	free(params.mountpoint);
	free(params.exec);

	for (char **ptr = args; *ptr; ptr++)
		free(*ptr);

	return status;
}
