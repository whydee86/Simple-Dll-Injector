#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <string>
#include "Helper.hpp"
using namespace std;

BOOL InjectToProcess(string ProcessName, string DllName)
{
	HANDLE hProcess;
	PVOID RemoteBuffer;
	PTHREAD_START_ROUTINE threatStartRoutineAddress;
	DWORD pid = NULL;
	if (ends_with(ProcessName, ".exe"))
	{
	    cout << "[*]Injecting: " << DllName << " To: " << ProcessName << endl;
	    pid = FindPidByName(ProcessName);
	}
	//find name by pid
	//cout << "[*]Injecting: " << DllName << " To: " << ProcessName << endl;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, strtol(ProcessName.c_str(), 0, 0));
	
	if (hProcess == NULL)
	{
	    cout << "Cannot open: " << FindPidByName(ProcessName) << ". Failed with Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	RemoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(DllName), MEM_COMMIT, PAGE_READWRITE);
	if (RemoteBuffer == NULL)
	{
		cout << "[-]Failed To Alloc Virtual Memory. Failed with Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	if (WriteProcessMemory(hProcess, RemoteBuffer, &DllName, sizeof(DllName), NULL) == FALSE)
	{
		cout << "[-]Failed To Write Process Memory. Failed with Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (CreateRemoteThread(hProcess, NULL, 0, threatStartRoutineAddress, RemoteBuffer, 0, NULL) == NULL)
	{
		cout << "[-]Failed To Create Remote Thread. Failed with Error Code: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return 0;
	}
	CloseHandle(hProcess);
	return 0;
}
