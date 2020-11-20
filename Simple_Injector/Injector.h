#pragma once
#include "Helper.h"

BOOL EnableDebugPriv()
{
    BOOL bRet = FALSE;
    HANDLE hToken = NULL;
    LUID luid = { 0 };

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        {
            TOKEN_PRIVILEGES tokenPriv = { 0 };
            tokenPriv.PrivilegeCount = 1;
            tokenPriv.Privileges[0].Luid = luid;
            tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
    }
    return bRet;
}



BOOL CheckIfDllIsLoad(DWORD pid, string DllName)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;
    BOOL There = FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL)
    {
        cout << "Cannot open Process ID: " << pid << ". Failed with Error Code: " << GetLastError() << endl;
        CloseHandle(hProcess);
        exit(-1);

    }

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                if (DllName == szModName)
                {
                    There = TRUE;
                }
            }
        }
    }
    CloseHandle(hProcess);
    return There;
}

BOOL InjectToProcess(DWORD pid, string DllName)
{
    HANDLE hProcess;
    PVOID RemoteBuffer;
    PTHREAD_START_ROUTINE threatStartRoutineAddress;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        cout << "Cannot open Process ID: " << pid << ". Failed with Error Code: " << GetLastError() << endl;
        CloseHandle(hProcess);
        exit(-1);
    }
    RemoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(DllName), MEM_COMMIT, PAGE_READWRITE);
    if (RemoteBuffer == NULL)
    {
        cout << "[-]Failed To Alloc Virtual Memory. Failed with Error Code: " << GetLastError() << endl;
        CloseHandle(hProcess);
        exit(-1);
    }
    if (WriteProcessMemory(hProcess, RemoteBuffer, &DllName, sizeof(DllName), NULL) == FALSE)
    {
        cout << "[-]Failed To Write Process Memory. Failed with Error Code: " << GetLastError() << endl;
        CloseHandle(hProcess);
        exit(-1);
    }
    threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (CreateRemoteThread(hProcess, NULL, 0, threatStartRoutineAddress, RemoteBuffer, 0, NULL) == NULL)
    {
        cout << "[-]Failed To Create Remote Thread. Failed with Error Code: " << GetLastError() << endl;
        CloseHandle(hProcess);
        exit(-1);
    }
    CloseHandle(hProcess);
    Sleep(1000);
    if (CheckIfDllIsLoad(pid, FullPath(DllName)))
    {
        cout << "[+]" << DllName << " Injected Successfully!" << endl;
    }
    else
    {
        cout << "[-]" << DllName << " Failed To load. Error Code: " << GetLastError() << endl;
    }
    return 0;
}