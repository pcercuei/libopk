#include "opk.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static bool display_info(char *package_path) {
	printf("=== %s\n", package_path);

	struct ParserData *opk = opk_open(package_path);
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
		printf("\nmetadata file: %s\n", metadata_name);
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
