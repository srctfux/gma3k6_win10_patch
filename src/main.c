// SPDX-License-Identifier: Unlicense

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "patch.h"
#include "resource.h"

HINSTANCE hInst;

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg) {
	case WM_INITDIALOG: {
			HBITMAP hBitmap = LoadBitmap(hInst, "B");
			HWND hEdit = GetDlgItem(hwndDlg, IDC_EDIT_CTRL);
			int ndx = GetWindowTextLength(hEdit);

			SendDlgItemMessage(hwndDlg, IDC_BITMAP_IMG, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hBitmap);
			SetFocus(hEdit);
			SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
					("Extract Win7_1096.exe with 7-Zip and\r\n"
					 "copy the patch to the Graphics directory and\r\n"
					 "patch the driver to make it compatible with\r\n"
					 "Windows 10 1607 and 1809.\r\n\r\n"));
			return TRUE;
	}
	case WM_CLOSE:
			EndDialog(hwndDlg, 0);
			return TRUE;
	case WM_NOTIFY:
			switch (((LPNMHDR)lParam)->code) {
			case NM_CLICK:
			case NM_RETURN:
				if (((LPNMHDR)lParam)->idFrom == IDC_SYSLINK)
					ShellExecute(hwndDlg, "open",
						"https://web.archive.org/web/20191014025013if_/https://downloadmirror.intel.com/23473/a08/Win7_1096.exe",
						NULL, NULL, SW_SHOWNORMAL);
				break;
			}
			return TRUE;
	case WM_COMMAND: {
			switch(LOWORD(wParam)) {
			case IDC_BUTTON_PATCH: {
					HWND hEdit = GetDlgItem(hwndDlg, IDC_EDIT_CTRL);
					int ret, ndx = 0;

					Button_Enable(hwndDlg, FALSE);
					ret = patchFiles(hEdit);
					switch (ret) {
					case FILE_NOT_OPEN:
							ndx = GetWindowTextLength(hEdit);
							SetFocus(hEdit);
							SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
							SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
									("Couldn't open files!\r\n"));
							break;
					case FILE_PATCH_OK:
							ndx = GetWindowTextLength(hEdit);
							SetFocus(hEdit);
							SendMessage(hEdit, EM_SETSEL, (WPARAM)ndx, (LPARAM)ndx);
							SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)
									("Install the driver with the 'have disk' method\r\n"
									 "and accept the unsigned driver prompt\r\n"));
							break;
					}
					Button_Enable(hwndDlg, TRUE);
					break;
			}
			case IDC_BUTTON_EXIT:
					PostQuitMessage(0);
					break;
			}
			return TRUE;
	}
	}
	return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	hInst = hInstance;
	InitCommonControls();
	return (int)DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)DlgMain);
}
