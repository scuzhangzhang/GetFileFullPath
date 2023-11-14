// GetFileFullPath.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "windows.h"
#include"tlhelp32.h"
#include"Strsafe.h"

#include "Psapi.h"
#include "ntos.h"

#include <iostream>
using namespace std;
//#include "Winternl.h"
PEB peb;

PROCESS_BASIC_INFORMATION pbi;
RTL_USER_PROCESS_PARAMETERS upps;
LPVOID zalloc(__in DWORD dwSize)
{
	LPBYTE pMem = (LPBYTE)malloc(dwSize);
	if (pMem != NULL) {
		RtlSecureZeroMemory(pMem, dwSize);
	}
	return(pMem);
}

VOID GetProcessInfo()
{
	UNICODE_STRING commandLine;
	WCHAR *commandLineContents;
	PVOID pebAddress;
	PVOID rtlUserProcParamsAddress;
	HINSTANCE hinstStub = GetModuleHandle(_T("ntdll.dll"));
	NtQueryInformationProcess = (LPNTQUERYINFORMATIONPROCESS)GetProcAddress(hinstStub, "NtQueryInformationProcess");
	NtReadVirtualMemory = (LPNTREADVIRTUALMEMORY)GetProcAddress(hinstStub, "NtReadVirtualMemory");
	if (!NtQueryInformationProcess)
	{
		printf("Could not find NtClose entry point in NTDLL.DLL");
		exit(0);
	}
	ULONG ReturnLength = 0;
	NTSTATUS status;
	
	HANDLE hSnapProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapProcess == INVALID_HANDLE_VALUE)
	{
		return;
	}
	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(ProcessEntry);
	BOOL bret = Process32FirstW(hSnapProcess, &ProcessEntry);
	WCHAR wszProcessInfo[MAX_PATH] = { 0 };

	do
	{
		WCHAR Name[MAX_PATH] = { 0 };
	
	    if (!lstrcmp(ProcessEntry.szExeFile, L"POWERPNT.EXE")| !lstrcmp(ProcessEntry.szExeFile, L"WINWORD.EXE"))
		{
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessEntry.th32ProcessID);
			status = NtQueryInformationProcess(hProcess,
				ProcessBasicInformation,
				&pbi,
				sizeof(PROCESS_BASIC_INFORMATION),
				&ReturnLength);
			pebAddress = pbi.PebBaseAddress;
			WCHAR *TMP;
			WCHAR *TMP1;
			WCHAR result[MAX_PATH] = {0};
			if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), 0))
				if (ReadProcessMemory(hProcess, peb.ProcessParameters, &upps, sizeof(RTL_USER_PROCESS_PARAMETERS), 0)) {
					WCHAR *buffer = new WCHAR[upps.CommandLine.Length + 1];
					ZeroMemory(buffer, (upps.CommandLine.Length + 1) * sizeof(WCHAR));
					ReadProcessMemory(hProcess, upps.CommandLine.Buffer, buffer, upps.CommandLine.Length, 0);
					WCHAR STR[MAX_PATH] = { 0 };
					lstrcat(STR, buffer);				
					TMP=wcschr(buffer, '"');
					TMP = wcschr(TMP+1, '"');
					TMP = wcschr(TMP + 1, '"');
					TMP1= wcsrchr(TMP + 1, '/');
					int len = lstrlen(TMP) - lstrlen(TMP1);
					wcsncpy(result, TMP, len);
					MessageBox(NULL, result, L"TEST", 1);
					delete buffer;
				}
			CloseHandle(hProcess);
		
		}
	
	} while (Process32NextW(hSnapProcess, &ProcessEntry));
	return;
}

int main()
{
	GetProcessInfo();
    return 0;
}

