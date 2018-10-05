#pragma once

#include "util.h"

namespace gh
{
    namespace hooking
    {
        // Apply the hook <hook> to a near call (opcode 0xE8) at <address> 
        // and return the address of the original destination.
        template <typename T>
        LPVOID hook_near_call(HANDLE handle, LPVOID address, LPVOID hook)
        {
            T  new_offset = static_cast<T>(reinterpret_cast<char*>(hook) - reinterpret_cast<char*>(address) - sizeof(T) - 1);
            boost::uint32_t old_protection = gh::memory::protect_memory<T>(handle, reinterpret_cast<LPVOID>(reinterpret_cast<char*>(address) + 1), PAGE_EXECUTE_READWRITE);

            T old_offset = gh::memory::read_memory<T>(handle, reinterpret_cast<LPVOID>(reinterpret_cast<char*>(address) + 1));
            if (!gh::memory::write_memory<T>(handle, reinterpret_cast<LPVOID>(reinterpret_cast<char*>(address) + 1), new_offset))
            {
                gh::error::print_error(GetLastError());
                return nullptr;
            }

            gh::memory::protect_memory<T>(handle, reinterpret_cast<LPVOID>(reinterpret_cast<char*>(address) + 1), old_protection);
            return reinterpret_cast<LPVOID>(old_offset + reinterpret_cast<char*>(address) + sizeof(T) + 1);
        }
    }
}