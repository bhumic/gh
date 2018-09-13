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
};