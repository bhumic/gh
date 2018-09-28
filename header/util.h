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

struct PROCESS_INFO
{
    boost::uint32_t pid;
    boost::uint32_t tid;
    LPVOID base;
    HANDLE handle;
    bool is64bit;
};

template <typename T>
void read_structure(const HANDLE& handle, LPVOID address, T& structure)
{
    boost::uint32_t old_protection = protect_memory<T>(handle, (LPVOID)address, PAGE_EXECUTE_READWRITE);
    structure = read_memory<T>(handle, (LPVOID)address);
    protect_memory<T>(handle, (LPVOID)address, old_protection);
}

LPVOID rebase(LPVOID address, LPVOID old_base, LPVOID new_base);

void print_error(boost::uint32_t error_code);

bool is_64bit(HANDLE& handle);

boost::uint32_t get_process_id(const HANDLE& snapshot, const std::string& exe_name);

boost::uint32_t get_thread_id(const HANDLE& snapshot, const boost::uint32_t& pid);

LPVOID get_process_base(const HANDLE& snapshot, const std::string& exe_name);

void get_process_info(const std::string exe_name, PROCESS_INFO& process_info);

HANDLE get_process_handle(boost::uint32_t pid);

HMODULE get_module_handle(const PROCESS_INFO& process_info, const std::string module_name);

template <typename T>
T read_memory(HANDLE handle, LPVOID address)
{
    T value;
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(handle, address, &value, sizeof(T), &bytes_read))
    {
        print_error(GetLastError());
    }

    return value;
}

template <typename T>
bool write_memory(HANDLE handle, LPVOID address, T value)
{
    SIZE_T bytes_written;
    if (!WriteProcessMemory(handle, address, &value, sizeof(T), &bytes_written))
    {
        print_error(GetLastError());
        return false;
    }

    return true;
}

boost::uint32_t protect_memory(HANDLE handle, LPVOID address, size_t size, boost::uint32_t protection);

template <typename T>
boost::uint32_t protect_memory(HANDLE handle, LPVOID address, boost::uint32_t protection)
{
    boost::uint32_t old_protection = 0;
    if (!VirtualProtectEx(handle, address, sizeof(T), protection, (PDWORD)&old_protection))
    {
        print_error(GetLastError());
    }

    return old_protection;
}