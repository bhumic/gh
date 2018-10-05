#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <string>
#include <iostream>
#include <vector>

#include "boost\cstdint.hpp"
#include "boost\shared_ptr.hpp"
#include "boost\make_shared.hpp"

#define MAX_HANDLES 1024

namespace gh
{
    namespace memory
    {
        // Read structure from memory
        template <typename T>
        void read_structure(const HANDLE& handle, LPVOID address, T& structure)
        {
            boost::uint32_t old_protection = protect_memory<T>(handle, (LPVOID)address, PAGE_EXECUTE_READWRITE);
            structure = read_memory<T>(handle, (LPVOID)address);
            protect_memory<T>(handle, (LPVOID)address, old_protection);
        }

        // Change protection flags on memory part
        template <typename T>
        boost::uint32_t protect_memory(HANDLE handle, LPVOID address, boost::uint32_t protection)
        {
            boost::uint32_t old_protection = 0;
            if (!VirtualProtectEx(handle, address, sizeof(T), protection, (PDWORD)&old_protection))
            {
                gh::error::print_error(GetLastError());
            }

            return old_protection;
        }

        // Read memory
        template <typename T>
        T read_memory(HANDLE handle, LPVOID address)
        {
            T value;
            SIZE_T bytes_read = 0;
            if (!ReadProcessMemory(handle, address, &value, sizeof(T), &bytes_read))
            {
                gh::error::print_error(GetLastError());
            }

            return value;
        }

        // Write Memory
        template <typename T>
        bool write_memory(HANDLE handle, LPVOID address, T value)
        {
            SIZE_T bytes_written;
            if (!WriteProcessMemory(handle, address, &value, sizeof(T), &bytes_written))
            {
                gh::error::print_error(GetLastError());
                return false;
            }

            return true;
        }

        // Write nop instructions to an address in memory
        template <size_t size>
        bool write_nop(HANDLE handle, LPVOID address)
        {
            boost::uint32_t old_protection = gh::memory::protect_memory<BYTE[size]>(handle, address, PAGE_EXECUTE_READWRITE);
            
            for (size_t i = 0; i < size; ++i)
            {
                if (!write_memory<BYTE>(handle, reinterpret_cast<LPVOID>(reinterpret_cast<char*>(address) + i), 0x90))
                {
                    gh::error::print_error(GetLastError());
                    return false;
                }
            }

            gh::memory::protect_memory<BYTE[size]>(handle, address, old_protection);

            return true;
        }

        // Protect memory based on size
        boost::uint32_t protect_memory(HANDLE handle, LPVOID address, size_t size, boost::uint32_t protection);
    }

    namespace process
    {
        // Structure containing all the important fields about a process
        struct PROCESS_INFO
        {
            boost::uint32_t pid;
            boost::uint32_t tid;
            LPVOID base;
            HANDLE handle;
            bool is64bit;
        };

        // Check if process is 64bit based on handle
        bool is_64bit(HANDLE& handle);

        // Retrieve the process ID
        boost::uint32_t get_process_id(const HANDLE& snapshot, const std::string& exe_name);

        // Retrieve the thread ID of main thread
        boost::uint32_t get_thread_id(const HANDLE& snapshot, const boost::uint32_t& pid);

        // Get base address of the process
        LPVOID get_process_base(const HANDLE& snapshot, const std::string& exe_name);

        // Populate the PROCESS_INFO structure with all the data
        void get_process_info(const std::string exe_name, gh::process::PROCESS_INFO& process_info);

        // Retrieve the handle of a process based on PID
        HANDLE get_process_handle(boost::uint32_t pid);

        // Retrieve the handle to the module 
        HMODULE get_module_handle(const gh::process::PROCESS_INFO& process_info, const std::string module_name);
    }

    namespace util
    {
        // Modify the address to the new base
        LPVOID rebase(LPVOID address, LPVOID old_base, LPVOID new_base);
    }

    namespace error
    {
        // Print the approppriate error message
        void print_error(boost::uint32_t error_code);
    }
}