#include "hook.h"

namespace gh
{
    namespace hooking
    {
        LPVOID hook_virtual_function(HANDLE handle, LPVOID instance, boost::uint32_t vf_index, LPVOID hook)
        {

            // Read the address of VF Table
            boost::uint32_t old_protection = gh::memory::protect_memory<LPVOID>(handle, instance, PAGE_EXECUTE_READWRITE);
            LPVOID vf_table = gh::memory::read_memory<LPVOID>(handle, instance);
            gh::memory::protect_memory<LPVOID>(handle, instance, old_protection);

            // Read the address of original Virtual Function
            LPVOID hook_index = reinterpret_cast<LPVOID>(reinterpret_cast<char*>(vf_table) + (vf_index * sizeof(LPVOID)));
            LPVOID vf_original = gh::memory::read_memory<LPVOID>(handle, hook_index);

            // Write the hook into the VF Table
            old_protection = gh::memory::protect_memory<LPVOID>(handle, instance, PAGE_READWRITE);
            gh::memory::write_memory<LPVOID>(handle, hook_index, hook);
            gh::memory::protect_memory<LPVOID>(handle, instance, old_protection);

            // Return the address of original function from VF table
            return vf_original;
        }
    }
}