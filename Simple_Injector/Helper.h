#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
using namespace std;

string FullPath(string file)
{
    char FileFullPath[MAX_PATH];
    if (GetFullPathName(file.c_str(), MAX_PATH, FileFullPath, nullptr) == FALSE)
    {
        cout << "[-]Cannot Get Full path of dll to check if is loaded. Error code: " << GetLastError();
    }
    return FileFullPath;

}

BOOL FileExits(string File)
{
    struct stat buffer;
    return (stat(File.c_str(), &buffer) == 0);
}

inline bool ends_with(std::string const& value, std::string const& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

DWORD FindPidByName(string ProcessName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot != NULL)
    {
        if (Process32First(snapshot, &entry) == 1)
        {
            if (!ProcessName.compare(entry.szExeFile))
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
            while (Process32Next(snapshot, &entry) == 1)
            {
                if (!ProcessName.compare(entry.szExeFile))
                {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            }
        }
    }
}


string FindNameByPid(DWORD pid)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot != NULL)
    {
        entry.dwSize = DWORD(sizeof(PROCESSENTRY32));
        if (Process32First(snapshot, &entry))
        {
            while (Process32Next(snapshot, &entry))
            {
                if (entry.th32ProcessID == pid)
                {
                    return entry.szExeFile;
                }
            }

        }
    }
}

DWORD GetPID(string ProcessPIDorName)
{
    if (ends_with(ProcessPIDorName, ".exe"))
    {
        return FindPidByName(ProcessPIDorName);
    }
    else
    {
        DWORD pid = atol(ProcessPIDorName.c_str());
        return pid;
    }
}

BOOL IsProcessRunnig(DWORD PID)
{
    BOOL exists = FALSE;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == NULL)
    {
        cout << "[-]Unable to check if the process is Running. Error code: " << GetLastError() << endl;
        return FALSE;
    }
    if (Process32First(snapshot, &entry))
    {
        while (Process32Next(snapshot, &entry))
        {
            if (PID == entry.th32ProcessID)
            {
                exists = TRUE;
            }
        }
        CloseHandle(snapshot);
        if (exists == FALSE)
        {
            return FALSE;
        }
        return exists;
    }
}



