#include "Helper.h"
#include "Injector.h"

int main(int argc, char* argv[])
{
    
    BOOL elevated = EnableDebugPriv();
    if (!elevated)
    {
        cout << "[!] Run as Administrator" << endl;
        exit(-1);
    }
    
    if (argc < 3 || argc > 4)
    {
        cout << "Usage: " << argv[0] << " Process Name Or Process ID | Dll To Load" << endl;
        exit(-1);
    }
    if (FileExits(FullPath(argv[2])))
    {
        
        if (IsProcessRunnig(GetPID(argv[1])))
        {
            cout << "[*]Process is Running" << endl;
            cout << "[*]Full Path of Dll: " << FullPath(argv[2]) << endl;
        }
        else
        {
            cout << "[-]Process Is Not Running" << endl;
            exit(-1);
        }
        if (CheckIfDllIsLoad(GetPID(argv[1]), FullPath(argv[2])))
        {
            cout << "[+]Dll is Already Loaded" << " To: " << FindNameByPid(GetPID(argv[1])) << "(" << GetPID(argv[1]) << ")" << endl;
            exit(-1);
        }
        else
        {
            cout << "[*]Injecting: " << argv[2] << " To: " << FindNameByPid(GetPID(argv[1])) << "(" << GetPID(argv[1]) << ")" << "..." << endl;
            InjectToProcess(GetPID(argv[1]), FullPath(argv[2]));
        }
    }
    else
    {
        cout << "[-]Dll was not found";
        exit(-1);
        
    }
    return 0;
}


