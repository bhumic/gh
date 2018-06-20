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
    LPVOID base;
    bool is64bit;
};

void print_error(boost::uint32_t error_code);

boost::uint32_t get_process_id(const boost::shared_ptr<void>& snapshot, const std::string& exe_name);

LPVOID get_process_base(const boost::shared_ptr<void>& snapshot, const std::string& exe_name);

void get_process_info(const std::string exe_name, PROCESS_INFO& process_info);

boost::shared_ptr<void> get_process_handle(boost::uint32_t pid);

template <typename T>
boost::shared_ptr<T> read_memory(HANDLE handle, LPVOID address)
{
    boost::shared_ptr<T> value = boost::make_shared<T>();
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(handle, address, (LPVOID)value.get(), sizeof(T), (SIZE_T*)&bytes_read))
    {
        print_error(GetLastError());
    }

    return value;
}

template <typename T>
bool write_memory(HANDLE handle, LPVOID address, boost::shared_ptr<T>& buffer)
{
    boost::uint32_t bytes_written;
    if (!WriteProcessMemory(handle, address, buffer.get(), sizeof(T), (SIZE_T*)&bytes_written))
    {
        print_error(GetLastError());
        return false;
    }

    return true;
}

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