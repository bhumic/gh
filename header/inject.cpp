#include "inject.h"

void injector_t::inject_shellcode(const PROCESS_INFO& process_info, const std::vector<BYTE>& shellcode)
{
   
    // Allocate memory for the shellcode
    LPVOID allocated = VirtualAllocEx(process_info.handle.get(), NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE);
    if (allocated == NULL)
    {
        print_error(GetLastError());
        return;
    }

    // TODO: injection part

    // Free the allocated memory
    if (!VirtualFreeEx(process_info.handle.get(), allocated, 0, MEM_RELEASE))
    {
        print_error(GetLastError());
        return;
    }
}