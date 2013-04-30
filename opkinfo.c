#include "opk.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static bool display_info(char *package_path) {
	printf("=== %s\n", package_path);

	struct OPK *opk = opk_open(package_path);
	if (!opk) {
		fprintf(stderr, "Failed to open %s\n", package_path);
		printf("\n");
		return false;
	}

	bool ok = true;

	while (true) {
		const char *metadata_name = opk_open_metadata(opk);
		if (!metadata_name) {
			break;
		}
		printf("\n");
		printf("Metadata file: %s\n\n", metadata_name);
		printf("Name:          %s\n", opk_read_param(opk, "Name"));
		printf("Comment:       %s\n", opk_read_param(opk, "Comment"));
		printf("Type:          %s\n", opk_read_param(opk, "Type"));
		printf("Categories:    %s\n", opk_read_param(opk, "Categories"));
		printf("Icon:          %s\n", opk_read_param(opk, "Icon"));
		printf("Exec:          %s\n", opk_read_param(opk, "Exec"));
		printf("Terminal:      %s\n", opk_read_param(opk, "Terminal"));
		printf("MimeType:      %s\n", opk_read_param(opk, "MimeType"));
		printf("X-OD-Manual:   %s\n", opk_read_param(opk, "X-OD-Manual"));
		printf("X-OD-Daemon:   %s\n", opk_read_param(opk, "X-OD-Daemon"));
	}

	opk_close(opk);

	printf("\n");
	return ok;
}

int main(int argc, char **argv) {
	if (argc == 1) {
		fprintf(stderr, "Usage: opkinfo app1.opk [app2.opk ...]\n");
		exit(2);
	}

	bool ok = true;
	for (int i = 1; i < argc; i++) {
		ok &= display_info(argv[i]);
	}
	exit(ok ? 0 : 1);
}
