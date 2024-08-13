/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: dllmain.c
 */
#ifdef _WIN32

#include <windows.h>

BOOLEAN WINAPI DllMain(HINSTANCE hinstDll, DWORD fwdReason, LPVOID lpvReserved)
{
	switch (fwdReason) {
		case DLL_PROCESS_ATTACH:
			break;
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

#endif
