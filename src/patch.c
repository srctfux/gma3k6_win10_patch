// SPDX-License-Identifier: Unlicense

#include <windows.h>
#include "Shlwapi.h"

#include "patch.h"
#include "resource.h"

#define TARGET_MAX_FILE_SIZE		(1536 * 1024)

#define TARGET_FILE_NAME_00		"igdlh.inf"
#define TARGET_BACK_NAME_00		"igdlh.inf.bak"
#define TARGET_SRC_SIZE_00		59795
#define TARGET_DEST_SIZE_00		60067
#define TARGET_SRC_CRC32_00		0x103685F6
#define TARGET_DEST_CRC32_00		0x6AE2A325

#define TARGET_FILE_NAME_01		"igdumd32.dll"
#define TARGET_BACK_NAME_01		"igdumd32.dll.bak"
#define TARGET_FILE_VERS_01		"8.14.8.1096"
#define TARGET_SRC_SIZE_01		1100800
#define TARGET_DEST_SIZE_01		1100800
#define TARGET_SRC_CRC32_01		0x117833ED
#define TARGET_DEST_CRC32_01		0x3073C54E

typedef struct tgFile {
	DWORD tgSrcSize;
	DWORD tgDestSize;
	uint32_t tgSrcCRC32;
	uint32_t tgDestCRC32;
	CHAR *tgFileName;
	CHAR *tgBackName;
	CHAR *tgFileVer;
} tgFile;

static int checkFileSrcSize(struct tgFile *targetFile)
{
	LARGE_INTEGER FileSrcSize;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFile(targetFile->tgFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING,
			   FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FILE_NOT_OPEN;

	if (!GetFileSizeEx(hFile, &FileSrcSize)) {
		CloseHandle(hFile);
		return FILE_NOT_OPEN;
	}
	CloseHandle(hFile);

	if (FileSrcSize.QuadPart != targetFile->tgSrcSize)
		return FILE_SIZE_ERR;

	return FILE_PATCH_OK;
}

static int checkFileSrcCRC32(struct tgFile *targetFile)
{
	CHAR *ReadBuf = malloc(TARGET_MAX_FILE_SIZE);
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	uint32_t FileCRC32;
	int ret;

	hFile = CreateFile(targetFile->tgFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING,
			   FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		ret = FILE_NOT_OPEN;
		goto out;
	}
	ReadFile(hFile, ReadBuf, targetFile->tgSrcSize, &dwBytesRead, NULL);
	CloseHandle(hFile);
	FileCRC32 = crc32(ReadBuf, targetFile->tgSrcSize);
	if (FileCRC32 != targetFile->tgSrcCRC32) {
		hFile = INVALID_HANDLE_VALUE;
		hFile = CreateFile(targetFile->tgFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING,
				   FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			ret = FILE_NOT_OPEN;
			goto out;
		}
		ReadFile(hFile, ReadBuf, targetFile->tgDestSize, &dwBytesRead, NULL);
		CloseHandle(hFile);
		FileCRC32 = crc32(ReadBuf, targetFile->tgDestSize);
		if (FileCRC32 == targetFile->tgDestCRC32) {
			ret = FILE_PATCHED;
			goto out;
		}
		ret = FILE_CRC32_ERR;
		goto out;
	}
	ret = FILE_PATCH_OK;

out:
	free(ReadBuf);
	return ret;
}

static int checkFileSrcVersion(struct tgFile *targetFile)
{
	DWORD FileVerInfoSize = 0;
	DWORD dwVerHandle = 0;

	FileVerInfoSize = GetFileVersionInfoSize(targetFile->tgFileName, &dwVerHandle);
	if (FileVerInfoSize) {
		LPSTR FileVerData[FileVerInfoSize];
		LPBYTE FileVerInfoBuf = NULL;
		UINT FileVerSize = 0;

		GetFileVersionInfo(targetFile->tgFileName, dwVerHandle, FileVerInfoSize, FileVerData);
		if (!VerQueryValue(FileVerData, "\\", (LPVOID *)&FileVerInfoBuf, &FileVerSize))
			goto err;

		if (FileVerSize) {
			CHAR tgFVerBuf[32];
			VS_FIXEDFILEINFO *FileVerInfo = (VS_FIXEDFILEINFO *)FileVerInfoBuf;
			DWORD dwFVMS = FileVerInfo->dwFileVersionMS;
			DWORD dwFVLS = FileVerInfo->dwFileVersionLS;

			snprintf(tgFVerBuf, sizeof(tgFVerBuf), "%d.%d.%d.%d",
				 HIWORD(dwFVMS), LOWORD(dwFVMS), HIWORD(dwFVLS), LOWORD(dwFVLS));
			if (strcmp(tgFVerBuf, targetFile->tgFileVer))
				goto err;
		} else
			goto err;
	} else
		goto err;

	return FILE_PATCH_OK;

err:
	return FILE_VER_ERR;
}

int patchFiles(HWND hEdit)
{
	struct tgFile *tg0 = malloc(sizeof(tgFile));
	struct tgFile *tg1 = malloc(sizeof(tgFile));
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesWritten = 0;
	DWORD dwBytesRead = 0;
	int ret = 0;
	int ndx = 0;

	CHAR tgReadBuf0[TARGET_SRC_SIZE_00];
	CHAR tgWriteBuf0[TARGET_DEST_SIZE_00];

	tg0->tgFileName  = TARGET_FILE_NAME_00;
	tg0->tgBackName  = TARGET_BACK_NAME_00;
	tg0->tgSrcSize   = TARGET_SRC_SIZE_00;
	tg0->tgDestSize  = TARGET_DEST_SIZE_00;
	tg0->tgSrcCRC32  = TARGET_SRC_CRC32_00;
	tg0->tgDestCRC32 = TARGET_DEST_CRC32_00;

	tg1->tgFileName  = TARGET_FILE_NAME_01;
	tg1->tgBackName  = TARGET_BACK_NAME_01;
	tg1->tgFileVer   = TARGET_FILE_VERS_01;
	tg1->tgSrcSize   = TARGET_SRC_SIZE_01;
	tg1->tgDestSize  = TARGET_DEST_SIZE_01;
	tg1->tgSrcCRC32  = TARGET_SRC_CRC32_01;
	tg1->tgDestCRC32 = TARGET_DEST_CRC32_01;

	/* Patch data igdlh.inf */
	/* Allow installation for certain versions of Windows 10 */
	const BYTE tgFile0Data0[] = {
		0x2C, 0x4E, 0x54, 0x78, 0x38, 0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30, 0x2C, 0x4E, 0x54,
		0x78, 0x38, 0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30, 0x2E, 0x2E, 0x2E, 0x31, 0x34, 0x33,
		0x39, 0x33, 0x2C, 0x4E, 0x54, 0x78, 0x38, 0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30, 0x2E,
		0x2E, 0x2E, 0x31, 0x35, 0x30, 0x36, 0x33, 0x2C, 0x4E, 0x54, 0x78, 0x38, 0x36, 0x2E,
		0x31, 0x30, 0x2E, 0x30, 0x2E, 0x2E, 0x2E, 0x31, 0x37, 0x37, 0x36, 0x33, 0x2C, 0x4E,
		0x54, 0x78, 0x38, 0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30, 0x2E, 0x2E, 0x2E, 0x31, 0x38,
		0x33, 0x36, 0x32, 0x0D, 0x0A, 0x0D, 0x0A, 0x5B, 0x49, 0x6E, 0x74, 0x65, 0x6C, 0x2E,
		0x4D, 0x66, 0x67, 0x2E, 0x4E, 0x54, 0x78, 0x38, 0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30,
		0x5D, 0x0D, 0x0A, 0x0D, 0x0A, 0x5B, 0x49, 0x6E, 0x74, 0x65, 0x6C, 0x2E, 0x4D, 0x66,
		0x67, 0x2E, 0x4E, 0x54, 0x78, 0x38, 0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30, 0x2E, 0x2E,
		0x2E, 0x31, 0x34, 0x33, 0x39, 0x33, 0x5D, 0x0D, 0x0A, 0x25, 0x69, 0x50, 0x4E, 0x57,
		0x44, 0x30, 0x25, 0x20, 0x3D, 0x20, 0x69, 0x43, 0x4E, 0x54, 0x30, 0x2C, 0x20, 0x50,
		0x43, 0x49, 0x5C, 0x56, 0x45, 0x4E, 0x5F, 0x38, 0x30, 0x38, 0x36, 0x26, 0x44, 0x45,
		0x56, 0x5F, 0x30, 0x42, 0x45, 0x30, 0x0D, 0x0A, 0x25, 0x69, 0x50, 0x4E, 0x57, 0x44,
		0x30, 0x25, 0x20, 0x3D, 0x20, 0x69, 0x43, 0x4E, 0x54, 0x30, 0x2C, 0x20, 0x50, 0x43,
		0x49, 0x5C, 0x56, 0x45, 0x4E, 0x5F, 0x38, 0x30, 0x38, 0x36, 0x26, 0x44, 0x45, 0x56,
		0x5F, 0x30, 0x42, 0x45, 0x31, 0x0D, 0x0A, 0x25, 0x69, 0x50, 0x4E, 0x57, 0x44, 0x30,
		0x25, 0x20, 0x3D, 0x20, 0x69, 0x43, 0x4E, 0x54, 0x30, 0x2C, 0x20, 0x50, 0x43, 0x49,
		0x5C, 0x56, 0x45, 0x4E, 0x5F, 0x38, 0x30, 0x38, 0x36, 0x26, 0x44, 0x45, 0x56, 0x5F,
		0x30, 0x42, 0x45, 0x32, 0x0D, 0x0A, 0x25, 0x69, 0x50, 0x4E, 0x57, 0x44, 0x30, 0x25,
		0x20, 0x3D, 0x20, 0x69, 0x43, 0x4E, 0x54, 0x30, 0x2C, 0x20, 0x50, 0x43, 0x49, 0x5C,
		0x56, 0x45, 0x4E, 0x5F, 0x38, 0x30, 0x38, 0x36, 0x26, 0x44, 0x45, 0x56, 0x5F, 0x30,
		0x42, 0x45, 0x33, 0x0D, 0x0A, 0x0D, 0x0A, 0x5B, 0x49, 0x6E, 0x74, 0x65, 0x6C, 0x2E,
		0x4D, 0x66, 0x67, 0x2E, 0x4E, 0x54, 0x78, 0x38, 0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30,
		0x2E, 0x2E, 0x2E, 0x31, 0x35, 0x30, 0x36, 0x33, 0x5D, 0x0D, 0x0A, 0x0D, 0x0A, 0x5B,
		0x49, 0x6E, 0x74, 0x65, 0x6C, 0x2E, 0x4D, 0x66, 0x67, 0x2E, 0x4E, 0x54, 0x78, 0x38,
		0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30, 0x2E, 0x2E, 0x2E, 0x31, 0x37, 0x37, 0x36, 0x33,
		0x5D, 0x0D, 0x0A, 0x25, 0x69, 0x50, 0x4E, 0x57, 0x44, 0x30, 0x25, 0x20, 0x3D, 0x20,
		0x69, 0x43, 0x4E, 0x54, 0x30, 0x2C, 0x20, 0x50, 0x43, 0x49, 0x5C, 0x56, 0x45, 0x4E,
		0x5F, 0x38, 0x30, 0x38, 0x36, 0x26, 0x44, 0x45, 0x56, 0x5F, 0x30, 0x42, 0x45, 0x30,
		0x0D, 0x0A, 0x25, 0x69, 0x50, 0x4E, 0x57, 0x44, 0x30, 0x25, 0x20, 0x3D, 0x20, 0x69,
		0x43, 0x4E, 0x54, 0x30, 0x2C, 0x20, 0x50, 0x43, 0x49, 0x5C, 0x56, 0x45, 0x4E, 0x5F,
		0x38, 0x30, 0x38, 0x36, 0x26, 0x44, 0x45, 0x56, 0x5F, 0x30, 0x42, 0x45, 0x31, 0x0D,
		0x0A, 0x25, 0x69, 0x50, 0x4E, 0x57, 0x44, 0x30, 0x25, 0x20, 0x3D, 0x20, 0x69, 0x43,
		0x4E, 0x54, 0x30, 0x2C, 0x20, 0x50, 0x43, 0x49, 0x5C, 0x56, 0x45, 0x4E, 0x5F, 0x38,
		0x30, 0x38, 0x36, 0x26, 0x44, 0x45, 0x56, 0x5F, 0x30, 0x42, 0x45, 0x32, 0x0D, 0x0A,
		0x25, 0x69, 0x50, 0x4E, 0x57, 0x44, 0x30, 0x25, 0x20, 0x3D, 0x20, 0x69, 0x43, 0x4E,
		0x54, 0x30, 0x2C, 0x20, 0x50, 0x43, 0x49, 0x5C, 0x56, 0x45, 0x4E, 0x5F, 0x38, 0x30,
		0x38, 0x36, 0x26, 0x44, 0x45, 0x56, 0x5F, 0x30, 0x42, 0x45, 0x33, 0x0D, 0x0A, 0x0D,
		0x0A, 0x5B, 0x49, 0x6E, 0x74, 0x65, 0x6C, 0x2E, 0x4D, 0x66, 0x67, 0x2E, 0x4E, 0x54,
		0x78, 0x38, 0x36, 0x2E, 0x31, 0x30, 0x2E, 0x30, 0x2E, 0x2E, 0x2E, 0x31, 0x38, 0x33,
		0x36, 0x32, 0x5D };

	/* Do not use MSI */
	const BYTE tgFile0Data1[] = { 0x30 };

	/* Enable 3D only for DWM */
	const BYTE tgFile0Data2[] = {
		0x57, 0x68, 0x69, 0x74, 0x65, 0x4C, 0x69, 0x73, 0x74, 0x65, 0x64, 0x41, 0x70, 0x70,
		0x73, 0x22, 0x2C, 0x25, 0x52, 0x45, 0x47, 0x5F, 0x53, 0x5A, 0x25, 0x2C, 0x22, 0x64,
		0x77, 0x6D };

	const DWORD tgFile0Offset[] = { 0x05C2, 0x0675, 0x4515, 0x4388, 0x7023, 0x6F31 };

	/* Patch data igdumd32.dll */
	const BYTE tgFile1Data0[][4] = {{ 0xE2, 0xEF, 0x10, 0x00 }, /* Fix PE checksum */
					{ 0x75, 0x09, 0xC7, 0x45 }, /* Convert registry blacklist into a whitelist */
					{ 0x57, 0x68, 0x69, 0x74 }, /* Replace UnsupportedApps with WhitelistedApps */
					{ 0x65, 0x4C, 0x69, 0x73 }};

	const DWORD tgFile1Offset[] = { 0x00140, 0x46C3B, 0xDFDB8, 0xDFDBC};

	/* Check target file igdlh.inf */
	if (!PathFileExists(tg0->tgFileName)) {
		ndx = GetWindowTextLength(hEdit);
		SetFocus(hEdit);
		SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
			((LPSTR)TARGET_FILE_NAME_00 " not found!\r\n"));
		ret = FILE_NOT_FOUND;
		goto checkTg1;
	}

	ret = checkFileSrcCRC32(tg0);
	switch (ret) {
	case FILE_PATCHED:
			ndx = GetWindowTextLength(hEdit);
			SetFocus(hEdit);
			SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
				((LPSTR)TARGET_FILE_NAME_00 " already patched!\r\n"));
			goto checkTg1;
	case FILE_CRC32_ERR:
			ndx = GetWindowTextLength(hEdit);
			SetFocus(hEdit);
			SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
				((LPSTR)TARGET_FILE_NAME_00 " incorrect checksum!\r\n"));
			goto checkTg1;
	case FILE_NOT_OPEN:
			goto out;
	}

	ret = checkFileSrcSize(tg0);
	switch (ret) {
	case FILE_SIZE_ERR:
			ndx = GetWindowTextLength(hEdit);
			SetFocus(hEdit);
			SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
				((LPSTR)TARGET_FILE_NAME_00 " incorrect file size!\r\n"));
			goto checkTg1;
	case FILE_NOT_OPEN:
			goto out;
	}

	/* Process igdlh.inf */
	CopyFile(tg0->tgFileName, tg0->tgBackName,FALSE);
	DeleteFile(tg0->tgFileName);
	hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(tg0->tgBackName, GENERIC_READ, 0, NULL, OPEN_EXISTING,
			   FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		ret = FILE_NOT_OPEN;
		goto out;
	}

	ReadFile(hFile, tgReadBuf0, sizeof(tgReadBuf0), &dwBytesRead, NULL);
	CloseHandle(hFile);

	/* String patch */
	for (UINT i = 0, j = 0; i < sizeof(tgWriteBuf0); i++, j++) {
		if (i == tgFile0Offset[0]) { /* Start offset - new file */
			for (UINT k = 0; k < sizeof(tgFile0Data0); k++, i++)
				tgWriteBuf0[i] = tgFile0Data0[k];
			j = tgFile0Offset[1]; /* Continue offset - old file */
		}
		if (i == tgFile0Offset[2]) { /* Start offset - new file */
			for (UINT k = 0; k < sizeof(tgFile0Data1); k++, i++)
				tgWriteBuf0[i] = tgFile0Data1[k];
			j = tgFile0Offset[3]; /* Continue offset - old file */
		}
		if (i == tgFile0Offset[4]) { /* Start offset - new file */
			for (UINT k = 0; k < sizeof(tgFile0Data2); k++, i++)
				tgWriteBuf0[i] = tgFile0Data2[k];
			j = tgFile0Offset[5]; /* Continue offset - old file */
		}
		tgWriteBuf0[i] = tgReadBuf0[j];
	}

	hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(tg0->tgFileName, GENERIC_WRITE, 0, NULL, CREATE_NEW,
			   FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		ret = FILE_NOT_OPEN;
		goto out;
	}

	WriteFile(hFile, tgWriteBuf0, sizeof(tgWriteBuf0), &dwBytesWritten, NULL);
	CloseHandle(hFile);

	ndx = GetWindowTextLength(hEdit);
	SetFocus(hEdit);
	SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)((LPSTR)TARGET_FILE_NAME_00 " patched!\r\n"));

	/* Check target file igdumd32.dll */
checkTg1:

	if (!PathFileExists(tg1->tgFileName)) {
		ndx = GetWindowTextLength(hEdit);
		SetFocus(hEdit);
		SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
			((LPSTR)TARGET_FILE_NAME_01 " not found!\r\n"));
		ret = FILE_NOT_FOUND;
		goto out;
	}

	ret = checkFileSrcCRC32(tg1);
	switch (ret) {
	case FILE_PATCHED:
			ndx = GetWindowTextLength(hEdit);
			SetFocus(hEdit);
			SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
				((LPSTR)TARGET_FILE_NAME_01 " already patched!\r\n"));
			ret = 0;
			goto out;
	case FILE_CRC32_ERR:
			ndx = GetWindowTextLength(hEdit);
			SetFocus(hEdit);
			SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
				((LPSTR)TARGET_FILE_NAME_01 " incorrect checksum!\r\n"));
			goto out;
	case FILE_NOT_OPEN:
			goto out;
	}

	ret = checkFileSrcSize(tg1);
	switch (ret) {
	case FILE_SIZE_ERR:
			ndx = GetWindowTextLength(hEdit);
			SetFocus(hEdit);
			SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
				((LPSTR)TARGET_FILE_NAME_01 " incorrect file size!\r\n"));
			goto out;
	case FILE_NOT_OPEN:
			goto out;
	}

	ret = checkFileSrcVersion(tg1);
	if (ret == FILE_VER_ERR) {
		ndx = GetWindowTextLength(hEdit);
		SetFocus(hEdit);
		SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
				((LPSTR)TARGET_FILE_NAME_01 " incorrect file version!\r\n"));
		goto out;
	}

	/* Process igdumd32.dll */
	CopyFile(tg1->tgFileName, tg1->tgBackName, FALSE);
	hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(tg1->tgFileName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
			   FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		ret = FILE_NOT_OPEN;
		goto out;
	}

	/* N offset -> N array */
	for (UINT i = 0; i < sizeof(tgFile1Data0) / sizeof(tgFile1Data0[0]); i++) {
		SetFilePointer(hFile, tgFile1Offset[i], 0, FILE_BEGIN);
		WriteFile(hFile, tgFile1Data0[i], sizeof(tgFile1Data0[i]), &dwBytesWritten, NULL);
	}
	CloseHandle(hFile);

	ndx = GetWindowTextLength(hEdit);
	SetFocus(hEdit);
	SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)((LPSTR)TARGET_FILE_NAME_01 " patched!\r\n"));

out:
	free(tg0);
	free(tg1);
	return ret;
}
