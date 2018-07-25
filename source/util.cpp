#include "util.h"

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

bool is_64bit(boost::shared_ptr<void>& handle)
{

    HMODULE dll_handle = GetModuleHandle("kernel32.dll");
    if (dll_handle != NULL)
    {
        typedef BOOL(WINAPI* p_iswow64)(HANDLE, PBOOL);
        p_iswow64 is_wow64 = (p_iswow64)GetProcAddress(dll_handle, "IsWow64Process");
        if (is_wow64 != NULL)
        {
            BOOL wow64 = false;
            if (is_wow64(handle.get(), &wow64))
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

boost::uint32_t get_process_id(const boost::shared_ptr<void>& snapshot, const std::string& exe_name)
{
    boost::uint32_t pid = 0;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot.get(), (LPPROCESSENTRY32)&entry))
    {
        if (!strcmp(exe_name.c_str(), entry.szExeFile))
        {
            return entry.th32ProcessID;
        }

        while (Process32Next(snapshot.get(), (LPPROCESSENTRY32)&entry))
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

LPVOID get_process_base(const boost::shared_ptr<void>& snapshot, const std::string& exe_name)
{
    LPVOID base = nullptr;

    MODULEENTRY32 entry;
    entry.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(snapshot.get(), (LPMODULEENTRY32)&entry))
    {
        if (!strcmp(exe_name.c_str(), entry.szModule))
        {
            return entry.modBaseAddr;
        }

        while (Module32Next(snapshot.get(), (LPMODULEENTRY32)&entry))
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
    boost::shared_ptr<void> snapshot_pid(CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0), CloseHandle);
    if (snapshot_pid.get() != INVALID_HANDLE_VALUE)
        process_info.pid = get_process_id(snapshot_pid, exe_name);
    else
        print_error(GetLastError());

    // get load address of process
    if (process_info.pid)
    {
        boost::shared_ptr<void> snapshot_base(CreateToolhelp32Snapshot(TH32CS_SNAPALL, process_info.pid), CloseHandle);
        if (snapshot_base.get() != INVALID_HANDLE_VALUE)
            process_info.base = get_process_base(snapshot_base, exe_name);
        else
            print_error(GetLastError());
    }

    // get process handle
    if (process_info.pid)
    {
        boost::shared_ptr<void> handle(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE 
                                                 | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
                                                 , false, process_info.pid), CloseHandle);
        if (handle.get() != NULL)
            process_info.handle = handle;
        else
            print_error(GetLastError());
    }

    // check if 64bit
    if (process_info.handle.get() != NULL)
    {
        process_info.is64bit = is_64bit(process_info.handle);
    }
}


boost::shared_ptr<void> get_process_handle(boost::uint32_t pid)
{
    boost::shared_ptr<void> handle(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, false, pid), CloseHandle);
    if (handle.get() == NULL)
    {
        print_error(GetLastError());
        return nullptr;
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