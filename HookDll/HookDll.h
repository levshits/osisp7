#include "stdafx.h"
#include "windows.h"

__declspec(dllexport) void Hook();
__declspec(dllexport) void UnHook();

__declspec(dllexport) DWORD Hook(void* oldProc, void* newProc, PCSTR pszCalleeModName);

__declspec(dllexport) int WINAPI HookMessageBoxW(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);
__declspec(dllexport) int WINAPI HookMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
__declspec(dllexport) BOOL WINAPI HookCloseHandle(_In_ HANDLE hObject);
__declspec(dllexport) HFILE WINAPI HookOpenFile(_In_   LPCSTR lpFileName, _Out_  LPOFSTRUCT lpReOpenBuff, _In_   UINT uStyle);
