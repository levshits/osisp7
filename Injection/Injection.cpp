// Injection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include "tlhelp32.h"

const char* HookLib = "C:\\Users\\Valentin\\Documents\\Visual Studio 2013\\Projects\\Injection\\Release\\HookDll.dll";

BOOL GetProcessList();
void printError(TCHAR* msg);
bool HookProcess(DWORD Pid);
int _tmain(int argc, _TCHAR* argv[])
{
	GetProcessList();
	while (1)
	{
		printf("\n\nPlease enter PID\n");
		DWORD Pid = 0;
		scanf("%d", &Pid);
		if (!HookProcess(Pid))
			printf("Process %d can't be hooked\n", Pid);
	}
	return 0;
}
bool HookProcess(DWORD Pid)
{
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
	LPVOID alloc = (LPVOID)VirtualAllocEx(process, 0, strlen(HookLib), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (alloc == NULL) return false;
	BOOL w = WriteProcessMemory(process, (LPVOID)alloc, HookLib, strlen(HookLib), 0);
	if (w == NULL) return false;
	LPVOID fp = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (fp == NULL) return false;
	HANDLE thread = CreateRemoteThread(process, 0, 0, (LPTHREAD_START_ROUTINE)fp, (LPVOID)alloc, 0, 0);
	if (thread == NULL) return false;
	CloseHandle(process);
	return true;
}
BOOL GetProcessList()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return(FALSE);
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		printError(TEXT("Process32First"));
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		_tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
		_tprintf(TEXT("\n  Process ID        = %d"), pe32.th32ProcessID);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return(TRUE);
}
void printError(TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		sysMsg, 256, NULL);
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));
	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}