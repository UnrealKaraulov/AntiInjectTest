// ��������� Windows XP ��� ����� Visual Studio
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501
#define NTDDI_VERSION 0x05010000
#define WIN32_LEAN_AND_MEAN
#define PSAPI_VERSION 1

// ����������� �������
#include <Windows.h>
#include <thread>
#include <string>
#include <vector>
#include <chrono>


// ReturnAddress
#include <intrin.h>
// NtQueryInformationThread
#include <winternl.h>
// ������ �����
#include "SimpleEncrypt.h"
// �������� WINAPI
#include "MinHook/include/MinHook.h"

// ���������� 
// ntdll.lib ��������� ��� ������ NtQueryInformationThread
#pragma comment(lib, "ntdll.lib")
// ��� MinHook
#pragma comment(lib, "libMinHook.x86.lib")

// �������� HMODULE �� ������ � ������. (x86)
HMODULE GetModuleFromAddress(DWORD addr)
{
	if (!addr)
		return 0;
	HMODULE hModule = NULL;
	GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
		(LPCWSTR)addr,
		&hModule);
	return hModule;
}

// ����� ������ ������ (x86)
DWORD GetThreadStartAddr(DWORD dwThreadId)
{
	HANDLE ThreadHandle = NULL;
	ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId);
	if (!ThreadHandle)
	{
		return 0;
	}

	NTSTATUS ntStatus;
	PVOID startAddress = NULL;
	ntStatus = NtQueryInformationThread(ThreadHandle, (THREADINFOCLASS)9/*start win32 address*/, &startAddress, sizeof(PVOID), NULL);
	if (NT_SUCCESS(ntStatus))
		return (DWORD)startAddress;

	return 0;
}

DWORD GetAddressProtection(LPVOID addr)
{
	DWORD oldprot;
	VirtualProtect(addr, 4, PAGE_EXECUTE_READ, &oldprot);
	VirtualProtect(addr, 4, oldprot, &oldprot);
	return oldprot;
}

// �������� �������� ������
bool AntihackScanCurrentThread()
{
	auto ThreadId = GetCurrentThreadId();

	auto ThreadStartAddr = GetThreadStartAddr(ThreadId);
	if (ThreadStartAddr == 0)
	{
		MessageBoxA(0, XorStr("Code inject found[HIDE START ADDRESS]"), XorStr("ANTIHACK"), 0);
		return false;
	}

	auto ThreadModule = GetModuleFromAddress(ThreadStartAddr);
	if (!ThreadModule)
	{
		MessageBoxA(0, XorStr("Code inject found[HIDE MODULE/CODE INJECTOR]"), XorStr("ANTIHACK"), 0);
		return false;
	}

	if (ThreadStartAddr == (DWORD)&LoadLibraryA || ThreadStartAddr == (DWORD)&LoadLibraryW)
	{
		MessageBoxA(0, XorStr("Code inject found[INJECTOR]"), XorStr("ANTIHACK"), 0);
		return false;
	}

	if (GetAddressProtection((LPVOID)ThreadStartAddr) == PAGE_EXECUTE_READWRITE)
	{
		MessageBoxA(0, XorStr("Code inject found[CODE INJECTOR]"), XorStr("ANTIHACK"), 0);
		return false;
	}

	return true;
}


DWORD WINAPI NULLTHREAD(LPVOID)
{
	// ����� ������� ������ ����� ��� �� �� �������
	while (true)
	{
		// �� �������� ������� �������� �� ������ ���� ����� ������� �������, ����� ����� ��������� ������ ������� � ���������� �� ����� ���������.
		Sleep(10000);
	}
	return 1;
}

typedef void* (__fastcall* pBaseThreadInitThunk)(int unk1, void* StartAddress, void* ThreadParameter);
pBaseThreadInitThunk BaseThreadInitThunk_org = nullptr;
pBaseThreadInitThunk BaseThreadInitThunk_ptr = nullptr;
void* __fastcall BaseThreadInitThunk_my(int unk1, PVOID StartAddress, PVOID ThreadParameter)
{
	DWORD retaddr = (DWORD)_ReturnAddress();

	if (!AntihackScanCurrentThread() || GetAddressProtection((LPVOID)StartAddress) == PAGE_EXECUTE_READWRITE)
	{
		MessageBoxA(0, XorStr("Base code inject found[CODE INJECTOR]"), XorStr("ANTIHACK"), 0);
		return BaseThreadInitThunk_ptr(unk1, NULLTHREAD, ThreadParameter);
	}

	return BaseThreadInitThunk_ptr(unk1, StartAddress, ThreadParameter);
}


/* ������ ������ */
struct ScanMemoryStruct
{
	DWORD address;
	DWORD value;

	DWORD protection;
	int protscanwait;

	std::string name;
};

std::vector<ScanMemoryStruct> scanMemory;

void AddScanMemory(DWORD address, const std::string& message)
{
	if (address == 0)
		return;
	scanMemory.push_back({ address, *(DWORD*)address, GetAddressProtection((LPVOID)address), 0 , message });
}

void AddScanMemory(const std::string& module, const std::string& function)
{
	auto dll = GetModuleHandle(module.c_str());
	if (!dll)
		dll = LoadLibrary(module.c_str());
	if (!dll)
	{
		MessageBoxA(0, (XorStr("Cant find scan module:") + module).c_str(), XorStr("Antihack"), 0);
		return;
	}
	DWORD addr = (DWORD)GetProcAddress(dll, function.c_str());
	if (!addr)
	{
		MessageBoxA(0, (XorStr("Cant add scan module:") + module + XorStr(". Funciton:") + function).c_str(), XorStr("Antihack"), 0);
		return;
	}

	scanMemory.push_back({ addr, *(DWORD*)addr, GetAddressProtection((LPVOID)addr), 0 ,XorStr("Module:") + module + XorStr(". Funciton:") + function });
}

// ������� ������ �������� ��� �������� (���������� ����)
void DumpScanMemoryDebug()
{
	std::ostringstream s;
	for (auto& i : scanMemory)
	{
		s << "Addr:" << std::hex << i.address << ". Name:" << i.name << std::endl;
	}
	MessageBoxA(0, s.str().c_str(), XorStr("ANTIHACK"), 0);
}

// ��������� ��� ������� �� ���������
bool IsValidScanMemory()
{
	for (auto& i : scanMemory)
	{
		if (*(DWORD*)i.address != i.value)
		{
			MessageBoxA(0, i.name.c_str(), XorStr("ANTIHACK. BAD MEMORY."), 0);
			return false;
		}
		i.protscanwait++;
		if (i.protscanwait > 25)
		{
			i.protscanwait = 0;

			if (GetAddressProtection((LPVOID)i.address) != i.protection)
			{
				MessageBoxA(0, i.name.c_str(), XorStr("ANTIHACK. BAD PROTECTION."), 0);
				return false;
			}
		}
	}
	return scanMemory.size() > 0;
}

// �������� ��� ����� ��������� ��� ����� ������������ ��������
int iScanCount = 0;

bool bStartScan = false;
// ������� ������������ ������ �� �������
void ScanThreadFunction()
{
	while (true)
	{
		if (bStartScan)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			if (!IsValidScanMemory())
			{
				MessageBoxA(0, XorStr("CHEATED!"), XorStr("ANTIHACK"), 0);
				continue;
			}
			iScanCount++;
			//std::this_thread::sleep_for(std::chrono::seconds(5));
			//DumpScanMemoryDebug();
		}
	}
}

//��������� ����� ������������
std::thread ScanThread = std::thread(ScanThreadFunction);

//��������� �����-������ ���
void CheatThreadFunction()
{
	std::this_thread::sleep_for(std::chrono::seconds(5));
	//��������� �����-������ ��� ��� �����
	LoadLibraryA("UltraCheat.dll");
}

std::thread CheatThread = std::thread(CheatThreadFunction);

BOOL __stdcall DllMain(HINSTANCE Module, unsigned int reason, LPVOID)
{
	// ������ ������� ��� ������������ ����������� �������
	if (reason == DLL_THREAD_ATTACH)
	{
		AntihackScanCurrentThread();
	}

	if (reason == DLL_PROCESS_ATTACH)
	{
		// ������ �������� DisableThreadLibraryCalls
		// ����� DLL_THREAD_ATTACH �� ����� ��������

		// ��� ���������������� ��� ��������� ������� ����� �������������� ��� �� �� ���� ���������
		// 
		// InitClientPatches();

		// ����������� ������ ������� �������� LoadLibrary � �.� ��� �� �������� ����� DLL �����������
		MH_Initialize();


		LoadLibraryA(XorStr("kernel32.dll"));
		LoadLibraryA(XorStr("ws2_32.dll"));
		LoadLibraryA(XorStr("opengl32.dll"));

		// ������ ������� ��� ������������ ����������� �������
		BaseThreadInitThunk_org = (pBaseThreadInitThunk)GetProcAddress(GetModuleHandle(XorStr("kernel32.dll")), XorStr("BaseThreadInitThunk"));
		if (BaseThreadInitThunk_org)
		{
			MH_CreateHook(BaseThreadInitThunk_org, &BaseThreadInitThunk_my, reinterpret_cast<void**>(&BaseThreadInitThunk_ptr));
			MH_EnableHook(BaseThreadInitThunk_org);
		}
		// ����� ��� ����������� GetModuleHandleA/W ��� �� ������ ������ �� �������, ������ ����� ��� hw.dll/client.dll � ��� �����



		// �� � ������� �������� ������ �������� ��� ������������
		// ������ ��� ������ ����� ���������� ���� ������.
		AddScanMemory((DWORD)LoadLibraryA, XorStr("LoadLibraryA - HOOKED!"));
		AddScanMemory((DWORD)LoadLibraryW, XorStr("LoadLibraryW - HOOKED!"));


		AddScanMemory((DWORD)BaseThreadInitThunk_org, XorStr("Error! AntiInjector - disabled!"));

		AddScanMemory(XorStr("ws2_32.dll"), XorStr("send"));
		AddScanMemory(XorStr("ws2_32.dll"), XorStr("recv"));
		AddScanMemory(XorStr("kernel32.dll"), XorStr("TerminateProcess"));


		AddScanMemory(XorStr("opengl32.dll"), XorStr("glDepthRange"));
		AddScanMemory(XorStr("opengl32.dll"), XorStr("glDisable"));
		AddScanMemory(XorStr("opengl32.dll"), XorStr("glBlendFunc"));
		AddScanMemory(XorStr("opengl32.dll"), XorStr("glVertex3fv"));
		// �������� ���� ��� ������ ��� ������

		// ������� ������ ������������ ��� ��� ������� ��������� � ����� ��������
		bStartScan = true;
	}
	else if (reason == DLL_PROCESS_DETACH)
	{
		bStartScan = false;
		// ����� ������� �� ���� ����� ����� ����� ������������ ��� �� �� ��������� ������� ������������ �� ������
		if (ScanThread.joinable())
			TerminateThread(reinterpret_cast<HANDLE>(ScanThread.native_handle()), 0); // ����������� ������
		MH_DisableHook(MH_ALL_HOOKS);
		MH_Uninitialize();
		//ExitProcess(0);
	}
	return TRUE;
}