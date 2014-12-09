// HookDll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "HookDll.h"
#include <Dbghelp.h>
#include <psapi.h>
#include "stdio.h"
#include "time.h"
#pragma comment(lib,"Dbghelp.lib")

const char* filename = "e:\\result.txt\0";
const char* MessageBoxMessage = "MessageBox";
const char* CloseHandleMessage = "CloseHandle";
const char* OpenFileMessage = "OpenFile";
const char* HookMessage = "Hooked";
const char* UnHookMessage = "Unhooked";

void logCalling(const char* message)
{
	FILE* file = fopen(filename, "a+");
	time_t Time;
	time(&Time);
	fprintf(file, "Pid %d %s %s", GetCurrentProcessId(), message, ctime(&Time));
	fclose(file);
}

void Hook()
{
	void* oldProc = GetProcAddress(GetModuleHandle(TEXT("user32.dll")), "MessageBoxW");
	void* newProc = HookMessageBoxW;
	char* moduleName = "user32.dll";
	 Hook(oldProc, newProc, moduleName);
	 oldProc = GetProcAddress(GetModuleHandle(TEXT("user32.dll")), "MessageBoxA");
	 newProc = HookMessageBoxA;
	 Hook(oldProc, newProc, moduleName);
	 moduleName = "Kernel32.dll";
	 oldProc = GetProcAddress(GetModuleHandle(TEXT("Kernel32.dll")), "CloseHandle");
	 newProc = HookCloseHandle;
	 Hook(oldProc, newProc, moduleName);
	 oldProc = GetProcAddress(GetModuleHandle(TEXT("Kernel32.dll")), "OpenFile");
	 newProc = HookOpenFile;
	 Hook(oldProc, newProc, moduleName);
	 logCalling(HookMessage);
}
void UnHook()
{
	void* oldProc = GetProcAddress(GetModuleHandle(TEXT("user32.dll")), "MessageBoxW");
	void* newProc = HookMessageBoxW;
	char* moduleName = "user32.dll";
	Hook(newProc, oldProc, moduleName);
	oldProc = GetProcAddress(GetModuleHandle(TEXT("user32.dll")), "MessageBoxA");
	newProc = HookMessageBoxA;
	Hook(newProc, oldProc, moduleName);
	moduleName = "Kernel32.dll";
	oldProc = GetProcAddress(GetModuleHandle(TEXT("Kernel32.dll")), "CloseHandle");
	newProc = HookCloseHandle;
	Hook(newProc, oldProc, moduleName);
	oldProc = GetProcAddress(GetModuleHandle(TEXT("Kernel32.dll")), "OpenFile");
	newProc = HookOpenFile;
	Hook(newProc, oldProc, moduleName);
	logCalling(UnHookMessage);
}

const HMODULE GetCurrentModule()
{
	DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS;
	HMODULE hm = 0;
	DWORD Pid = GetCurrentProcessId();
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
	EnumProcessModules(handle, &hm, sizeof(HMODULE), NULL);
	CloseHandle(handle);
	return hm;
}

DWORD Hook(void* oldProc, void* newProc, PCSTR pszCalleeModName)
{
	DWORD result = 0;
	ULONG ulSize;
	HANDLE hmodCaller = GetCurrentModule();
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

	if (pImportDesc == NULL) return result;

	for (; pImportDesc->Name; pImportDesc++)
	{
		PSTR pszModName = (PSTR)((PBYTE)hmodCaller + pImportDesc->Name);

		if (lstrcmpiA(pszModName, pszCalleeModName) == 0) break;
	}

	PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hmodCaller + pImportDesc->FirstThunk);

	for (; pThunk->u1.Function; pThunk++)
	{
		if ((PROC)pThunk->u1.Function == oldProc)
		{
			DWORD old = 0;
			VirtualProtect(&pThunk->u1.Function, 4, PAGE_READWRITE, &old);
			pThunk->u1.Function = (DWORD)newProc;
			result = pThunk->u1.Function;
			VirtualProtect(&pThunk->u1.Function, 4, PAGE_READONLY, &old);


		}
	}
	return result;
}

int WINAPI HookMessageBoxW(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType)
{
	logCalling(MessageBoxMessage);
	return MessageBoxW(hWnd, lpText, lpCaption, uType);
}

int WINAPI HookMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	logCalling(MessageBoxMessage);
	return MessageBoxA(hWnd, lpText, lpCaption, uType);
}

BOOL WINAPI HookCloseHandle(_In_ HANDLE hObject)
{
	logCalling(CloseHandleMessage);
	return CloseHandle(hObject);
}
HFILE WINAPI HookOpenFile(_In_   LPCSTR lpFileName, _Out_  LPOFSTRUCT lpReOpenBuff, _In_   UINT uStyle)
{
	logCalling(OpenFileMessage);
	return OpenFile(lpFileName, lpReOpenBuff, uStyle);
}
