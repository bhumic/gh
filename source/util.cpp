#include "util.h"

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

    boost::shared_ptr<void> snapshot_pid(CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0), CloseHandle);
    if (snapshot_pid.get() != INVALID_HANDLE_VALUE)
        process_info.pid = get_process_id(snapshot_pid, exe_name);
    else
        print_error(GetLastError());

    boost::shared_ptr<void> snapshot_base(CreateToolhelp32Snapshot(TH32CS_SNAPALL, process_info.pid), CloseHandle);
    if (snapshot_base.get() != INVALID_HANDLE_VALUE)
        process_info.base = get_process_base(snapshot_base, exe_name);
    else
        print_error(GetLastError());
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