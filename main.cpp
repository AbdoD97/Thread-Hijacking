#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

using namespace std;

int main()
{
    HANDLE processesSnap    = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, NULL);
    LPPROCESSENTRY32  currentProcess  = (LPPROCESSENTRY32)new PROCESSENTRY32();
    currentProcess->dwSize = sizeof(PROCESSENTRY32);
    while (Process32Next(processesSnap,currentProcess ))
    {

        // cout <<currentProcess->szExeFile << endl;
        if (strcmp(currentProcess->szExeFile, "Hey.exe") ==0  )
            break;
    }
    cout << currentProcess->szExeFile <<endl;
    char DllPath [] = "C:\\helloworld.dll";

    HANDLE hProcess =  OpenProcess(PROCESS_ALL_ACCESS, 0,currentProcess->th32ProcessID);
    LPVOID addy = VirtualAllocEx( hProcess
                                  ,0, sizeof(DllPath),MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SIZE_T x = 0;
    //cout << sizeof(DllPath) << endl;
    cout << addy << endl;

    HMODULE hKernel32 =  GetModuleHandleA ("Kernel32");
    FARPROC fxAddy = GetProcAddress(hKernel32, "LoadLibraryA");
    cout << "loadlib  " << hex << fxAddy << endl;

    WriteProcessMemory(hProcess,addy, &DllPath, sizeof(DllPath),&x ) ;


    HANDLE threadSnap  = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, currentProcess->th32ProcessID);

    LPTHREADENTRY32 currentThread  = (LPTHREADENTRY32)new THREADENTRY32();
    currentThread->dwSize =  sizeof(THREADENTRY32);

    while (Thread32Next(threadSnap,currentThread))
    {

        if (currentThread->th32OwnerProcessID == currentProcess->th32ProcessID)
            break;
    }

    cout << "Thread id is " << currentThread->th32ThreadID << endl;


    HANDLE hThread =  OpenThread(THREAD_ALL_ACCESS,0,currentThread->th32ThreadID);


    unsigned char shell [] = { 0xB8, 0x67, 0x45, 0x23, 0x01, 0x50, 0xB8, 0xEF, 0xCD, 0xAB, 0x89, 0xFF, 0xD0 };

    PDWORD ptr = (PDWORD) (shell+1);

    *ptr = (DWORD)addy; //setting the param
    cout << (DWORD)addy << endl;
    ptr = (PDWORD) (shell+7);

    *ptr = (DWORD)fxAddy;

    cout << (DWORD)fxAddy << endl;

   PVOID shelladdy = VirtualAllocEx(hProcess , 0,sizeof(shell) , MEM_COMMIT | MEM_RESERVE ,PAGE_EXECUTE_READWRITE );
   WriteProcessMemory(hProcess,shelladdy,(LPCVOID)shell , sizeof(shell) , &x);

    SuspendThread(hThread);
    LPCONTEXT context = (LPCONTEXT) new CONTEXT();
    context->ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, context);
    context->Eip = (DWORD)shelladdy; //LoadLibrary + parameter
    SetThreadContext(hThread, context);
cout << "EIP IS " << hex <<context->Eip << endl;
    ResumeThread(hThread);



    return 0;
}
