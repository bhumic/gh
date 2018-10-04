#pragma once

#include "util.h"
#include "pe.h"

namespace gh
{
    namespace injector
    {
        // Base class for all of the injection classes
        class injector_t
        {
        public:
            // inject shellcode into a process described with PROCESS_INFO and execute it via CreateRemoteThread API
            static void inject_shellcode_crt(const gh::process::PROCESS_INFO& process_info, const std::vector<BYTE>& shellcode);
            // inject shellcode into a process described with PROCESS_INFO and execute it via Main Thread Hijacking method (x64)
            static void inject_shellcode_mth(const gh::process::PROCESS_INFO& process_info, std::vector<BYTE> shellcode);
            // inject DLL into a process
            static void inject_dll(const gh::process::PROCESS_INFO& process_info, const std::string& dll_path);
            // eject dll from the process
            static void eject_dll(const gh::process::PROCESS_INFO& process_info, const std::string dll_name);
        };
    }
}