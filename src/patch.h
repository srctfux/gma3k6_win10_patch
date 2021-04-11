/* SPDX-License-Identifier: Unlicense */

#ifndef PATCH_H
#define PATCH_H

#include <stdio.h>
#include <stdint.h>

enum {
	FILE_PATCH_OK = 0,
	FILE_PATCHED,
	FILE_NOT_FOUND,
	FILE_NOT_OPEN,
	FILE_VER_ERR,
	FILE_SIZE_ERR,
	FILE_CRC32_ERR,
};

int patchFiles(HWND hEdit);
uint32_t crc32(const char *data, uint32_t n_bytes);

#endif /* PATCH_H */
