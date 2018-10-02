#include "util.h"

#include <boost/algorithm/string.hpp>

LPVOID rebase(LPVOID address, LPVOID old_base, LPVOID new_base)
{
    return reinterpret_cast<LPVOID>(reinterpret_cast<char*>(address) - reinterpret_cast<char*>(old_base) + reinterpret_cast<char*>(new_base));
}

void print_error(boost::uint32_t error_code)
{
    LPTSTR msg = nullptr;
    if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
        | FORMAT_MESSAGE_FROM_SYSTEM
        | FORMAT_MESSAGE_IGNORE_INSERTS
        , 0
        , error_code
        , 0
        , (LPTSTR)&msg
        , 65532
        , nullptr))
    {
        print_error(GetLastError());
    }
    else
    {
        std::wcout << msg << std::endl;
    }
}

bool is_64bit(HANDLE& handle)
{

    HMODULE dll_handle = GetModuleHandle("kernel32.dll");
    if (dll_handle != NULL)
    {
        typedef BOOL(WINAPI* p_iswow64)(HANDLE, PBOOL);
        p_iswow64 is_wow64 = (p_iswow64)GetProcAddress(dll_handle, "IsWow64Process");
        if (is_wow64 != NULL)
        {
            BOOL wow64 = false;
            if (is_wow64(handle, &wow64))
            {
                return !wow64;
            }
            else
                print_error(GetLastError());
        }
        else
            print_error(GetLastError());
    }
    else
        print_error(GetLastError());

    return false;
}

boost::uint32_t get_process_id(const HANDLE& snapshot, const std::string& exe_name)
{
    boost::uint32_t pid = 0;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, (LPPROCESSENTRY32)&entry))
    {
        if (!strcmp(exe_name.c_str(), entry.szExeFile))
        {
            return entry.th32ProcessID;
        }

        while (Process32Next(snapshot, (LPPROCESSENTRY32)&entry))
        {
            if (!strcmp(exe_name.c_str(), entry.szExeFile))
            {
                return entry.th32ProcessID;
            }
        }
    }
    else
        print_error(GetLastError());

    return pid;
}

boost::uint32_t get_thread_id(const HANDLE& snapshot, const boost::uint32_t& pid)
{

    THREADENTRY32 entry;
    // must be initialized prior to use
    entry.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(snapshot, &entry))
    {
        if (entry.th32OwnerProcessID == pid)
            return entry.th32ThreadID;

        while (Thread32Next(snapshot, &entry))
        {
            if (entry.th32OwnerProcessID == pid)
                return entry.th32ThreadID;
        }
    }
    else
        print_error(GetLastError());

    return 0;
}

LPVOID get_process_base(const HANDLE& snapshot, const std::string& exe_name)
{
    LPVOID base = nullptr;

    MODULEENTRY32 entry;
    entry.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(snapshot, (LPMODULEENTRY32)&entry))
    {
        if (!strcmp(exe_name.c_str(), entry.szModule))
        {
            return entry.modBaseAddr;
        }

        while (Module32Next(snapshot, (LPMODULEENTRY32)&entry))
        {
            if (!strcmp(exe_name.c_str(), entry.szModule))
            {
                return entry.modBaseAddr;
            }
        }
    }
    else
        print_error(GetLastError());

    return nullptr;
}

void get_process_info(const std::string exe_name, PROCESS_INFO& process_info)
{
    // get PID of process
    HANDLE snapshot_pid = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (snapshot_pid != INVALID_HANDLE_VALUE)
        process_info.pid = get_process_id(snapshot_pid, exe_name);
    else
        print_error(GetLastError());
    CloseHandle(snapshot_pid);

    // get load address of process
    if (process_info.pid)
    {
        HANDLE snapshot_base = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_info.pid);
        if (snapshot_base != INVALID_HANDLE_VALUE)
            process_info.base = get_process_base(snapshot_base, exe_name);
        else
            print_error(GetLastError());
        CloseHandle(snapshot_base);
    }

    // get process handle
    if (process_info.pid)
    {
        HANDLE handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE 
                                  | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
                                  , false, process_info.pid);
        if (handle != NULL)
            process_info.handle = handle;
        else
            print_error(GetLastError());
    }

    // get ID of main thread
    if (process_info.pid)
    {
        HANDLE snapshot_tid = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot_tid != INVALID_HANDLE_VALUE)
            process_info.tid = get_thread_id(snapshot_tid, process_info.pid);
        else
            print_error(GetLastError());
        CloseHandle(snapshot_tid);
    }

    // check if 64bit
    if (process_info.handle != NULL)
    {
        process_info.is64bit = is_64bit(process_info.handle);
    }
}


HANDLE get_process_handle(boost::uint32_t pid)
{
    HANDLE handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, false, pid);
    if (handle == NULL)
    {
        print_error(GetLastError());
        return nullptr;
    }

    return handle;
}

HMODULE get_module_handle(const PROCESS_INFO& process_info, const std::string module_name)
{

    HMODULE handle = NULL;
    if (process_info.pid)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_info.pid);
        if (snapshot != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32 entry;
            entry.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(snapshot, (LPMODULEENTRY32)&entry))
            {
                if (module_name == boost::algorithm::to_lower_copy(std::string(entry.szModule)))
                {
                    handle = entry.hModule;
                }

                while (Module32Next(snapshot, (LPMODULEENTRY32)&entry))
                {
                    if (module_name == boost::algorithm::to_lower_copy(std::string(entry.szModule)))
                    {
                        handle =  entry.hModule;
                        break;
                    }
                }
            }
            else
                print_error(GetLastError());
        }
        else
            print_error(GetLastError());
        CloseHandle(snapshot);
    }

    return handle;
}

boost::uint32_t protect_memory(HANDLE handle, LPVOID address, size_t size, boost::uint32_t protection)
{
    boost::uint32_t old_protection = 0;
    if (!VirtualProtectEx(handle, address, size, protection, (PDWORD)&old_protection))
    {
        print_error(GetLastError());
    }

    return old_protection;
}